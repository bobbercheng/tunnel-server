package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// wsHandler handles WebSocket connections from agents
func wsHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	secret := r.URL.Query().Get("secret")

	if id == "" || secret == "" {
		http.Error(w, "missing id or secret", http.StatusBadRequest)
		return
	}

	// Verify tunnel exists and secret matches
	tunnelsMu.RLock()
	tunnel, exists := tunnels[id]
	tunnelsMu.RUnlock()

	if !exists || tunnel.Secret != secret {
		http.Error(w, "invalid id or secret", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{"tunnel"},
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("WebSocket accept failed: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "server error")

	ac := &agentConn{
		id:               id,
		secret:           secret,
		ws:               conn,
		connectedAt:      time.Now(),
		waiters:          make(map[string]chan *RespFrame),
		tcpConns:         make(map[string]*TcpConn),
		chunkedResponses: make(map[string]*ChunkedResponse),
		lastPong:         time.Now(),
	}

	// Register agent
	agentsMu.Lock()
	agents[id] = ac
	agentsMu.Unlock()

	defer func() {
		agentsMu.Lock()
		delete(agents, id)
		agentsMu.Unlock()

		// Close all TCP connections
		ac.tcpConnsMu.Lock()
		for _, tcpConn := range ac.tcpConns {
			tcpConn.close("agent disconnected")
		}
		ac.tcpConnsMu.Unlock()

		log.Printf("Agent %s disconnected", id)
	}()

	// Perform key exchange
	if err := performKeyExchange(r.Context(), ac); err != nil {
		log.Printf("Key exchange failed for agent %s: %v", id, err)
		return
	}

	log.Printf("Agent %s connected with encrypted tunnel (protocol: %s)", id, tunnel.Protocol)

	// Start ping routine for connection health monitoring
	go ac.pingRoutine(r.Context())

	// Handle messages
	for {
		var msgType websocket.MessageType
		var data []byte
		msgType, data, err = conn.Read(r.Context())
		if err != nil {
			log.Printf("WebSocket read error for agent %s: %v", id, err)
			break
		}

		if msgType != websocket.MessageBinary {
			log.Printf("Unexpected message type from agent %s: %v", id, msgType)
			continue
		}

		go ac.handleMessage(data)
	}
}

// performKeyExchange handles the initial key exchange with the agent
func performKeyExchange(ctx context.Context, ac *agentConn) error {
	// Generate salt for key derivation
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Send handshake with salt
	handshake := &HandshakeFrame{
		Type: "handshake",
		Salt: base64.StdEncoding.EncodeToString(salt),
	}

	if err := wsjson.Write(ctx, ac.ws, handshake); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Create cipher with derived keys
	cipher, err := crypto.NewStreamCipher([]byte(ac.secret), salt, true)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	ac.cipher = cipher

	// Wait for acknowledgment (plain text "handshake" message)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, ackData, err := ac.ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read ack: %w", err)
	}

	var ackMsg map[string]interface{}
	if err := json.Unmarshal(ackData, &ackMsg); err != nil {
		return fmt.Errorf("failed to parse ack: %w", err)
	}

	if ackMsg["type"] != "handshake" || ackMsg["ack"] != true {
		return fmt.Errorf("expected handshake ack message, got: %v", ackMsg)
	}

	return nil
}

// registerWaiter registers a channel to wait for a response
func (ac *agentConn) registerWaiter(reqID string, ch chan *RespFrame) {
	ac.respMu.Lock()
	defer ac.respMu.Unlock()
	ac.waiters[reqID] = ch
}

// writeEncrypted writes an encrypted message to the WebSocket
func (ac *agentConn) writeEncrypted(ctx context.Context, msg interface{}) error {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	if ac.cipher == nil {
		return fmt.Errorf("cipher not initialized")
	}

	encryptedData, err := ac.cipher.Encrypt(data)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	return ac.ws.Write(ctx, websocket.MessageBinary, encryptedData)
}

// handleMessage processes incoming messages from the agent
func (ac *agentConn) handleMessage(encryptedData []byte) {
	if ac.cipher == nil {
		log.Printf("Received message before key exchange completed for agent %s", ac.id)
		return
	}

	// Decrypt message
	data, err := ac.cipher.Decrypt(encryptedData)
	if err != nil {
		log.Printf("Failed to decrypt message from agent %s: %v", ac.id, err)
		return
	}

	// Parse message type
	var baseMsg struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &baseMsg); err != nil {
		log.Printf("Failed to parse message type from agent %s: %v", ac.id, err)
		return
	}

	switch baseMsg.Type {
	case "resp":
		ac.handleResponse(data)
	case "chunked_resp":
		ac.handleChunkedResponse(data)
	case "tcp_data":
		ac.handleTCPData(data)
	case "tcp_disconnect":
		ac.handleTCPDisconnect(data)
	case "pong":
		ac.handlePong(data)
	case "tunnel_info":
		ac.handleTunnelInfo(data)
	default:
		log.Printf("Unknown message type from agent %s: %s", ac.id, baseMsg.Type)
	}
}

// handleResponse processes HTTP response messages
func (ac *agentConn) handleResponse(data []byte) {
	var resp RespFrame
	if err := json.Unmarshal(data, &resp); err != nil {
		log.Printf("Failed to parse response from agent %s: %v", ac.id, err)
		return
	}

	ac.respMu.Lock()
	ch, exists := ac.waiters[resp.ReqID]
	if exists {
		delete(ac.waiters, resp.ReqID)
	}
	ac.respMu.Unlock()

	if exists {
		select {
		case ch <- &resp:
		case <-time.After(1 * time.Second):
			log.Printf("Timeout sending response for reqID %s from agent %s", resp.ReqID, ac.id)
		}
	}
}

// handleChunkedResponse processes chunked HTTP response messages
func (ac *agentConn) handleChunkedResponse(data []byte) {
	var chunk ChunkedRespFrame
	if err := json.Unmarshal(data, &chunk); err != nil {
		log.Printf("Failed to parse chunked response from agent %s: %v", ac.id, err)
		return
	}

	ac.chunkedMu.Lock()
	defer ac.chunkedMu.Unlock()

	// Get or create chunked response tracker
	chunkedResp, exists := ac.chunkedResponses[chunk.ReqID]
	if !exists {
		chunkedResp = &ChunkedResponse{
			ReqID:       chunk.ReqID,
			Status:      chunk.Status,
			Headers:     chunk.Headers,
			Chunks:      make(map[int][]byte),
			TotalChunks: chunk.TotalChunks,
			Received:    0,
			LastSeen:    time.Now(),
		}
		ac.chunkedResponses[chunk.ReqID] = chunkedResp
	}

	// Store chunk
	chunkedResp.Chunks[chunk.ChunkIndex] = chunk.Data
	chunkedResp.Received++
	chunkedResp.LastSeen = time.Now()

	// Check if all chunks received
	if chunkedResp.Received >= chunkedResp.TotalChunks || chunk.IsLast {
		// Assemble complete response
		var completeBody []byte
		for i := 0; i < chunkedResp.TotalChunks; i++ {
			if chunkData, exists := chunkedResp.Chunks[i]; exists {
				completeBody = append(completeBody, chunkData...)
			}
		}

		// Create complete response
		resp := &RespFrame{
			Type:    "resp",
			ReqID:   chunk.ReqID,
			Status:  chunkedResp.Status,
			Headers: chunkedResp.Headers,
			Body:    completeBody,
		}

		// Send to waiter
		ac.respMu.Lock()
		ch, exists := ac.waiters[chunk.ReqID]
		if exists {
			delete(ac.waiters, chunk.ReqID)
		}
		ac.respMu.Unlock()

		if exists {
			select {
			case ch <- resp:
			case <-time.After(1 * time.Second):
				log.Printf("Timeout sending chunked response for reqID %s from agent %s", chunk.ReqID, ac.id)
			}
		}

		// Clean up
		delete(ac.chunkedResponses, chunk.ReqID)
	}
}

// handleTCPData processes TCP data messages
func (ac *agentConn) handleTCPData(data []byte) {
	var tcpData TcpDataFrame
	if err := json.Unmarshal(data, &tcpData); err != nil {
		log.Printf("Failed to parse TCP data from agent %s: %v", ac.id, err)
		return
	}

	ac.tcpConnsMu.Lock()
	tcpConn, exists := ac.tcpConns[tcpData.ConnID]
	ac.tcpConnsMu.Unlock()

	if exists && !tcpConn.closed {
		select {
		case tcpConn.dataCh <- tcpData.Data:
		case <-time.After(1 * time.Second):
			log.Printf("Timeout sending TCP data for connection %s from agent %s", tcpData.ConnID, ac.id)
		}
	}
}

// handleTCPDisconnect processes TCP disconnect messages
func (ac *agentConn) handleTCPDisconnect(data []byte) {
	var tcpDisconnect TcpDisconnectFrame
	if err := json.Unmarshal(data, &tcpDisconnect); err != nil {
		log.Printf("Failed to parse TCP disconnect from agent %s: %v", ac.id, err)
		return
	}

	ac.tcpConnsMu.Lock()
	tcpConn, exists := ac.tcpConns[tcpDisconnect.ConnID]
	if exists {
		delete(ac.tcpConns, tcpDisconnect.ConnID)
	}
	ac.tcpConnsMu.Unlock()

	if exists {
		tcpConn.close(tcpDisconnect.Reason)
	}
}

// handlePong processes pong messages for connection health monitoring
func (ac *agentConn) handlePong(data []byte) {
	var pong PongFrame
	if err := json.Unmarshal(data, &pong); err != nil {
		log.Printf("Failed to parse pong from agent %s: %v", ac.id, err)
		return
	}

	ac.pingMu.Lock()
	ac.lastPong = time.Now()
	ac.pingMu.Unlock()
}

// handleTunnelInfo processes tunnel info messages during reconnection
func (ac *agentConn) handleTunnelInfo(data []byte) {
	var tunnelInfo TunnelInfoFrame
	if err := json.Unmarshal(data, &tunnelInfo); err != nil {
		log.Printf("Failed to parse tunnel info from agent %s: %v", ac.id, err)
		return
	}

	// Update tunnel information if needed
	tunnelsMu.Lock()
	if tunnel, exists := tunnels[ac.id]; exists {
		tunnel.Protocol = tunnelInfo.Protocol
		tunnel.Port = tunnelInfo.Port
		log.Printf("Updated tunnel info for agent %s: protocol=%s, port=%d", ac.id, tunnelInfo.Protocol, tunnelInfo.Port)
	}
	tunnelsMu.Unlock()
}

// pingRoutine sends periodic ping messages to monitor connection health
func (ac *agentConn) pingRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if we haven't received a pong in too long
			ac.pingMu.RLock()
			lastPong := ac.lastPong
			ac.pingMu.RUnlock()

			if time.Since(lastPong) > 2*time.Minute {
				log.Printf("Agent %s appears to be unresponsive (no pong in %v)", ac.id, time.Since(lastPong))
				// Could implement connection reset here
			}

			// Send ping
			ping := &PingFrame{
				Type:      "ping",
				Timestamp: time.Now(),
			}

			if err := ac.writeEncrypted(ctx, ping); err != nil {
				log.Printf("Failed to send ping to agent %s: %v", ac.id, err)
				return
			}
		}
	}
}

// close closes a TCP connection
func (tc *TcpConn) close(reason string) {
	tc.closeMu.Lock()
	defer tc.closeMu.Unlock()

	if tc.closed {
		return
	}

	tc.closed = true
	close(tc.dataCh)
	select {
	case tc.closeCh <- reason:
	default:
	}
	close(tc.closeCh)
}

// getAgent retrieves an agent connection by ID
func getAgent(id string) *agentConn {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	return agents[id]
}
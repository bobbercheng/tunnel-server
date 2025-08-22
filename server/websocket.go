package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// wsHandler handles WebSocket connections from agents
func wsHandler(w http.ResponseWriter, r *http.Request) {
	// Check if this is a new connection (no id/secret) or existing agent reconnection
	id := r.URL.Query().Get("id")
	secret := r.URL.Query().Get("secret")

	var existingTunnel *TunnelInfo
	var isReconnection bool

	if id != "" && secret != "" {
		// This is a reconnection attempt - verify tunnel exists and secret matches
		tunnelsMu.RLock()
		tunnel, exists := tunnels[id]
		tunnelsMu.RUnlock()

		if !exists || tunnel.Secret != secret {
			http.Error(w, "invalid id or secret", http.StatusUnauthorized)
			return
		}
		existingTunnel = tunnel
		isReconnection = true
	}
	// If no id/secret provided, this is a new connection that will register over WebSocket

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:       []string{"tunnel"},
		InsecureSkipVerify: true,
	})
	if err == nil {
		// Set read limit to 20MB to handle large encrypted messages (crypto MaxPlaintextSize is 16MB + encryption overhead)
		conn.SetReadLimit(20 * 1024 * 1024)
	}
	if err != nil {
		log.Printf("WebSocket accept failed: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "server error")

	// Extract client IP and perform geolocation lookup
	clientIP := extractRealClientIP(r)
	geoData := lookupIPGeoData(clientIP)

	ac := &agentConn{
		id:               id,     // Will be empty for new connections until registration
		secret:           secret, // Will be empty for new connections until registration
		ws:               conn,
		connectedAt:      time.Now(),
		clientIP:         clientIP,
		geoData:          geoData,
		waiters:          make(map[string]chan *RespFrame),
		tcpConns:         make(map[string]*TcpConn),
		chunkedResponses: make(map[string]*ChunkedResponse),
		lastPong:         time.Now(),
	}

	// For reconnections, register agent immediately
	if isReconnection {
		agentsMu.Lock()
		agents[id] = ac
		agentsMu.Unlock()
		// Record WebSocket connection metric
		tunnelMetrics.IncrementWSConnection(id)

		// CRITICAL FIX: Restore custom URL mapping for reconnection
		if existingTunnel.CustomURL != "" {
			customURLsMu.Lock()
			customURLs[existingTunnel.CustomURL] = id
			customURLsMu.Unlock()
			log.Printf("[RECONNECTION] Restored custom URL mapping | TunnelID: %s | CustomURL: %s | ClientIP: %s", id, existingTunnel.CustomURL, clientIP)
		}
	}

	defer func() {
		if ac.id != "" { // Only clean up if agent was fully registered
			agentsMu.Lock()
			delete(agents, ac.id)
			agentsMu.Unlock()

			// Record WebSocket disconnection metric
			tunnelMetrics.DecrementWSConnection(ac.id)

			// Clean up custom URL mappings for this tunnel
			cleanupCustomURLsForTunnel(ac.id)

			// Clean up affinities for this tunnel
			if affinityManager != nil {
				affinityManager.ClearTunnelAffinities(ac.id)
			}

			// Close all TCP connections
			ac.tcpConnsMu.Lock()
			for _, tcpConn := range ac.tcpConns {
				tcpConn.close("agent disconnected")
			}
			ac.tcpConnsMu.Unlock()

			if ac.geoData != nil && ac.geoData.Country != "" {
				if ac.geoData.City != "" {
					log.Printf("Agent %s disconnected from %s, %s, %s (%s)", ac.id, ac.geoData.Country, ac.geoData.Region, ac.geoData.City, ac.clientIP)
				} else {
					log.Printf("Agent %s disconnected from %s, %s (%s)", ac.id, ac.geoData.Country, ac.geoData.Region, ac.clientIP)
				}
			} else {
				log.Printf("Agent %s disconnected from %s", ac.id, ac.clientIP)
			}
		}
	}()

	// Perform key exchange with temporary secret for new connections
	var keyExchangeSecret string
	if isReconnection {
		keyExchangeSecret = secret
	} else {
		// For new connections, use a well-known temporary secret for key exchange
		// The real secret will be generated during registration
		keyExchangeSecret = "temp_handshake_secret_for_registration"
		ac.secret = keyExchangeSecret
	}

	if err := performKeyExchange(r.Context(), ac, keyExchangeSecret); err != nil {
		log.Printf("Key exchange failed for agent: %v", err)
		return
	}

	if isReconnection {
		if geoData != nil && geoData.Country != "" {
			if geoData.City != "" {
				log.Printf("Agent %s reconnected with encrypted tunnel (protocol: %s) from %s, %s, %s (%s)", id, existingTunnel.Protocol, geoData.Country, geoData.Region, geoData.City, clientIP)
			} else {
				log.Printf("Agent %s reconnected with encrypted tunnel (protocol: %s) from %s, %s (%s)", id, existingTunnel.Protocol, geoData.Country, geoData.Region, clientIP)
			}
		} else {
			log.Printf("Agent %s reconnected with encrypted tunnel (protocol: %s) from %s", id, existingTunnel.Protocol, clientIP)
		}
	} else {
		if geoData != nil && geoData.Country != "" {
			if geoData.City != "" {
				log.Printf("New agent connected from %s, %s, %s (%s), waiting for registration", geoData.Country, geoData.Region, geoData.City, clientIP)
			} else {
				log.Printf("New agent connected from %s, %s (%s), waiting for registration", geoData.Country, geoData.Region, clientIP)
			}
		} else {
			log.Printf("New agent connected from %s, waiting for registration", clientIP)
		}
		// Handle registration over encrypted WebSocket
		if err := handleWebSocketRegistration(r.Context(), ac); err != nil {
			log.Printf("Registration failed for new agent: %v", err)
			return
		}
	}

	// Create connection-specific context for proper cleanup coordination
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel() // Ensure all goroutines are cancelled when connection closes

	// Start ping routine for connection health monitoring
	go ac.pingRoutine(connCtx)

	// Handle messages with connection context for proper cleanup
	for {
		var msgType websocket.MessageType
		var data []byte
		msgType, data, err = conn.Read(context.Background()) // Use background to avoid context cancellation issues
		if err != nil {
			log.Printf("WebSocket read error for agent %s: %v", id, err)
			connCancel() // Cancel our connection context to stop all related goroutines
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
func performKeyExchange(ctx context.Context, ac *agentConn, secret string) error {
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

	// Create cipher with derived keys (hash the secret like the agent does)
	masterSecret := sha256.Sum256([]byte(secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, true)
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

// handleWebSocketRegistration handles agent registration over encrypted WebSocket
func handleWebSocketRegistration(ctx context.Context, ac *agentConn) error {
	// Wait for registration message
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, regData, err := ac.ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read registration: %w", err)
	}

	// Decrypt registration message
	decryptedData, err := ac.cipher.Decrypt(regData)
	if err != nil {
		return fmt.Errorf("failed to decrypt registration: %w", err)
	}

	var regFrame RegisterFrame
	if err := json.Unmarshal(decryptedData, &regFrame); err != nil {
		return fmt.Errorf("failed to parse registration: %w", err)
	}

	if regFrame.Type != "register" {
		return fmt.Errorf("expected register frame, got: %s", regFrame.Type)
	}

	// Validate registration data
	if regFrame.Protocol == "" {
		regFrame.Protocol = "http"
	}
	if regFrame.Protocol != "http" && regFrame.Protocol != "tcp" {
		return sendRegistrationError(ac, "protocol must be 'http' or 'tcp'")
	}
	if regFrame.Protocol == "tcp" && regFrame.Port <= 0 {
		return sendRegistrationError(ac, "port is required for TCP tunnels")
	}

	// Validate custom URL if provided
	if err := validateCustomURL(regFrame.CustomURL); err != nil {
		return sendRegistrationError(ac, fmt.Sprintf("invalid custom URL: %s", err.Error()))
	}

	// Check if custom URL is available (will do atomic check during registration)
	if regFrame.CustomURL != "" {
		// Do atomic availability check and registration later
	}

	// Generate tunnel ID and secret
	id := uuid.NewString()
	secret := randHex(32)

	// Normalize custom URL
	var normalizedCustomURL string
	if regFrame.CustomURL != "" {
		normalizedCustomURL = strings.Trim(regFrame.CustomURL, "/")
	}

	// Create tunnel info
	tunnelInfo := &TunnelInfo{
		Secret:      secret,
		Protocol:    regFrame.Protocol,
		Port:        regFrame.Port,
		Created:     time.Now(),
		CustomURL:   normalizedCustomURL,
		UseRedirect: regFrame.UseRedirect,
	}

	// Register tunnel
	tunnelsMu.Lock()
	tunnels[id] = tunnelInfo
	tunnelsMu.Unlock()

	// Register custom URL mapping if provided (atomic check and registration)
	if normalizedCustomURL != "" {
		customURLsMu.Lock()
		// Atomic check: verify custom URL is still available
		if existingTunnelID, exists := customURLs[normalizedCustomURL]; exists {
			customURLsMu.Unlock()
			// Clean up the tunnel that was already registered
			tunnelsMu.Lock()
			delete(tunnels, id)
			tunnelsMu.Unlock()
			log.Printf("[REGISTRATION CONFLICT] Custom URL: %s already taken by tunnel: %s | Rejected tunnel: %s | Method: WebSocket | Client IP: %s", normalizedCustomURL, existingTunnelID, id, ac.clientIP)
			return sendRegistrationError(ac, "custom URL is already taken")
		}
		customURLs[normalizedCustomURL] = id
		customURLsMu.Unlock()
		log.Printf("[REGISTRATION] Tunnel ID: %s | Custom URL: %s | Method: WebSocket | Client IP: %s", id, normalizedCustomURL, ac.clientIP)
	} else {
		log.Printf("Registered tunnel %s (WebSocket)", id)
	}

	// Update agent connection with real ID and secret
	ac.id = id
	ac.secret = secret

	// Register agent in active connections
	agentsMu.Lock()
	agents[id] = ac
	agentsMu.Unlock()

	// Record WebSocket connection metric
	tunnelMetrics.IncrementWSConnection(id)

	// Build URLs
	publicBase := os.Getenv("PUBLIC_BASE_URL")
	if publicBase == "" {
		// Since we're in WebSocket context, we need to reconstruct the base URL
		// We'll use a default scheme and assume standard port
		publicBase = "https://localhost" // This will need to be configured properly
	}

	var publicURL string
	var tcpPort int
	if regFrame.Protocol == "tcp" {
		publicURL = fmt.Sprintf("%s/__tcp__/%s", publicBase, id)
		tcpPort = regFrame.Port
	} else {
		publicURL = fmt.Sprintf("%s/__pub__/%s", publicBase, id)
	}

	var customURLResponse string
	if normalizedCustomURL != "" {
		customURLResponse = fmt.Sprintf("%s/%s", publicBase, normalizedCustomURL)
	}

	// Send registration response
	response := &RegisterResponseFrame{
		Type:        "register_response",
		ID:          id,
		Secret:      secret,
		PublicURL:   publicURL,
		CustomURL:   customURLResponse,
		Protocol:    regFrame.Protocol,
		TcpPort:     tcpPort,
		UseRedirect: regFrame.UseRedirect,
		Success:     true,
	}

	return ac.writeEncrypted(ctx, response)
}

// sendRegistrationError sends an encrypted error response for registration
func sendRegistrationError(ac *agentConn, errorMsg string) error {
	response := &RegisterResponseFrame{
		Type:    "register_response",
		Success: false,
		Error:   errorMsg,
	}
	return ac.writeEncrypted(context.Background(), response)
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

	// Use background context for WebSocket writes to avoid connection closure
	// from request timeout contexts
	err = ac.ws.Write(context.Background(), websocket.MessageBinary, encryptedData)
	if err == nil && ac.id != "" {
		// Record outbound WebSocket message metric
		tunnelMetrics.RecordWSMessage(ac.id, "sent")
	}
	return err
}

// handleMessage processes incoming messages from the agent
func (ac *agentConn) handleMessage(encryptedData []byte) {
	if ac.cipher == nil {
		log.Printf("Received message before key exchange completed for agent %s", ac.id)
		return
	}

	// Record inbound WebSocket message metric
	if ac.id != "" {
		tunnelMetrics.RecordWSMessage(ac.id, "received")
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
	case "streaming_start":
		ac.handleStreamingStart(data)
	case "streaming_chunk":
		ac.handleStreamingChunk(data)
	case "streaming_end":
		ac.handleStreamingEnd(data)
	case "websocket_upgrade_success":
		ac.handleWebSocketUpgradeSuccess(data)
	case "websocket_frame":
		ac.handleWebSocketFrame(data)
	case "websocket_close":
		ac.handleWebSocketClose(data)
	case "tcp_data":
		ac.handleTCPData(data)
	case "tcp_disconnect":
		ac.handleTCPDisconnect(data)
	case "ping":
		ac.handlePing(data)
	case "pong":
		ac.handlePong(data)
	case "tunnel_info":
		ac.handleTunnelInfo(data)
	case "register":
		// Registration should be handled during initial connection, not here
		log.Printf("Unexpected register message from agent %s", ac.id)
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

// handlePing processes ping messages from the agent and sends pong response
func (ac *agentConn) handlePing(data []byte) {
	var ping PingFrame
	if err := json.Unmarshal(data, &ping); err != nil {
		log.Printf("Failed to parse ping from agent %s: %v", ac.id, err)
		return
	}

	// Validate tunnel ID matches
	if ping.TunnelID != ac.id {
		log.Printf("Warning: Received ping with mismatched tunnel ID from agent %s (expected: %s, got: %s)", ac.id, ac.id, ping.TunnelID)
		// Still respond to maintain connection, but log the mismatch
	}

	// Respond with pong, echoing the tunnel ID
	pong := &PongFrame{
		Type:      "pong",
		Timestamp: ping.Timestamp,
		TunnelID:  ping.TunnelID, // Echo back the tunnel ID from ping
	}

	if err := ac.writeEncrypted(context.Background(), pong); err != nil {
		log.Printf("Failed to send pong to agent %s: %v", ac.id, err)
	}
}

// handlePong processes pong messages for connection health monitoring
func (ac *agentConn) handlePong(data []byte) {
	var pong PongFrame
	if err := json.Unmarshal(data, &pong); err != nil {
		log.Printf("Failed to parse pong from agent %s: %v", ac.id, err)
		return
	}

	// Validate tunnel ID matches
	if pong.TunnelID != ac.id {
		log.Printf("Warning: Received pong with mismatched tunnel ID from agent %s (expected: %s, got: %s)", ac.id, ac.id, pong.TunnelID)
		// Still update last pong time to maintain connection, but log the mismatch
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

		// CRITICAL FIX: Restore custom URL mapping when tunnel info is updated
		if tunnel.CustomURL != "" {
			tunnelsMu.Unlock() // Unlock tunnels before locking customURLs to avoid deadlock
			customURLsMu.Lock()
			customURLs[tunnel.CustomURL] = ac.id
			customURLsMu.Unlock()
			log.Printf("[TUNNEL INFO] Restored custom URL mapping | TunnelID: %s | CustomURL: %s | ClientIP: %s", ac.id, tunnel.CustomURL, ac.clientIP)
			tunnelsMu.Lock() // Re-lock for the deferred unlock
		}
	}
	tunnelsMu.Unlock()
}

// pingRoutine sends periodic ping messages to monitor connection health
func (ac *agentConn) pingRoutine(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Check immediately on startup for already expired connections (timeout check only, no ping)
	ac.pingMu.RLock()
	lastPong := ac.lastPong
	ac.pingMu.RUnlock()

	if time.Since(lastPong) > 3*time.Minute { // More lenient for cloud environments
		log.Printf("Agent %s appears to be unresponsive (no pong in %v), forcing connection close", ac.id, time.Since(lastPong))
		// Force close the WebSocket to trigger cleanup
		ac.ws.Close(websocket.StatusGoingAway, "unresponsive")
		return
	}

	checkAndPing := func() bool {
		// Check if we haven't received a pong in too long
		ac.pingMu.RLock()
		lastPong := ac.lastPong
		ac.pingMu.RUnlock()

		if time.Since(lastPong) > 3*time.Minute { // More lenient for cloud environments
			log.Printf("Agent %s appears to be unresponsive (no pong in %v), forcing connection close", ac.id, time.Since(lastPong))
			// Force close the WebSocket to trigger cleanup
			ac.ws.Close(websocket.StatusGoingAway, "unresponsive")
			return false // Signal to stop
		}

		// Send ping with tunnel ID
		ping := &PingFrame{
			Type:      "ping",
			Timestamp: time.Now(),
			TunnelID:  ac.id,
		}

		if err := ac.writeEncrypted(ctx, ping); err != nil {
			log.Printf("Failed to send ping to agent %s: %v", ac.id, err)
			return false // Signal to stop
		}
		return true // Continue
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !checkAndPing() {
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

// validateAndCleanupStaleConnections checks for and removes stale agent connections
// This is called on server startup to handle connections that may have persisted
// from before a server restart but are no longer valid
func validateAndCleanupStaleConnections() {
	agentsMu.Lock()
	defer agentsMu.Unlock()

	if len(agents) == 0 {
		log.Println("Connection validation: No existing connections to validate")
		return
	}

	staleConnections := make([]*agentConn, 0)
	validConnections := 0

	// Check each connection for staleness indicators
	for id, conn := range agents {
		if isConnectionStale(conn) {
			log.Printf("Connection validation: Marking agent %s as stale (connected %v ago, last pong %v ago)",
				id, time.Since(conn.connectedAt), time.Since(conn.lastPong))
			staleConnections = append(staleConnections, conn)
		} else {
			validConnections++
		}
	}

	log.Printf("Connection validation: Found %d valid connections, %d stale connections",
		validConnections, len(staleConnections))

	// Close stale connections asynchronously to avoid blocking server startup
	if len(staleConnections) > 0 {
		go func() {
			for _, conn := range staleConnections {
				closeStaleConnection(conn, "server restart validation")
			}
		}()
	}
}

// isConnectionStale determines if a connection should be considered stale
func isConnectionStale(conn *agentConn) bool {
	now := time.Now()

	// Connection is stale if:
	// 1. Last pong is older than 30 seconds (likely disconnected during restart)
	// 2. Connection time is more than 5 minutes old but no recent pong activity
	// 3. Connection was made before the current server process started (if we could detect that)

	timeSinceLastPong := now.Sub(conn.lastPong)
	timeSinceConnect := now.Sub(conn.connectedAt)

	// If last pong is older than 30 seconds, likely stale
	if timeSinceLastPong > 30*time.Second {
		return true
	}

	// If connected more than 5 minutes ago but no pong in last minute, likely stale
	if timeSinceConnect > 5*time.Minute && timeSinceLastPong > 1*time.Minute {
		return true
	}

	return false
}

// closeStaleConnection safely closes a stale connection
func closeStaleConnection(conn *agentConn, reason string) {
	if conn == nil || conn.ws == nil {
		return
	}

	// Close the WebSocket connection
	err := conn.ws.Close(websocket.StatusGoingAway, reason)
	if err != nil {
		log.Printf("Error closing stale connection for agent %s: %v", conn.id, err)
	} else {
		log.Printf("Closed stale connection for agent %s: %s", conn.id, reason)
	}
}

// schedulePeriodicConnectionValidation sets up a routine to periodically validate connections
// This provides ongoing monitoring in addition to startup validation
func schedulePeriodicConnectionValidation() {
	go func() {
		// Run validation every 5 minutes
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			agentsMu.RLock()
			connectionCount := len(agents)
			agentsMu.RUnlock()

			if connectionCount > 0 {
				log.Printf("Periodic connection validation: Checking %d connections", connectionCount)
				validateAndCleanupStaleConnections()
			}
		}
	}()
}

// handleStreamingStart processes the start of a streaming response
func (ac *agentConn) handleStreamingStart(data []byte) {
	var frame ChunkedRespFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse streaming_start from agent %s: %v", ac.id, err)
		return
	}

	log.Printf("SERVER STREAMING: Starting stream | ReqID: %s | AgentID: %s | Status: %d", 
		frame.ReqID, ac.id, frame.Status)

	// Get the waiting HTTP response writer
	ac.respMu.Lock()
	ch, exists := ac.waiters[frame.ReqID]
	if !exists {
		ac.respMu.Unlock()
		log.Printf("SERVER STREAMING: No waiter found for streaming start | ReqID: %s | AgentID: %s", 
			frame.ReqID, ac.id)
		return
	}
	
	// Send initial response to start streaming
	resp := &RespFrame{
		Type:    "streaming_start",
		ReqID:   frame.ReqID,
		Status:  frame.Status,
		Headers: frame.Headers,
		Body:    []byte{}, // Empty body for start frame
	}
	
	// Send to waiter without removing it (streaming continues)
	select {
	case ch <- resp:
		log.Printf("SERVER STREAMING: Sent streaming_start to waiter | ReqID: %s", frame.ReqID)
	default:
		log.Printf("SERVER STREAMING: Failed to send streaming_start (channel full) | ReqID: %s", frame.ReqID)
	}
	ac.respMu.Unlock()
}

// handleStreamingChunk processes streaming data chunks
func (ac *agentConn) handleStreamingChunk(data []byte) {
	var frame ChunkedRespFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse streaming_chunk from agent %s: %v", ac.id, err)
		return
	}

	log.Printf("SERVER STREAMING: Received chunk %d (%d bytes) | ReqID: %s | AgentID: %s", 
		frame.ChunkIndex, len(frame.Data), frame.ReqID, ac.id)

	// Get the waiting HTTP response writer
	ac.respMu.Lock()
	ch, exists := ac.waiters[frame.ReqID]
	if !exists {
		ac.respMu.Unlock()
		log.Printf("SERVER STREAMING: No waiter found for streaming chunk | ReqID: %s | AgentID: %s", 
			frame.ReqID, ac.id)
		return
	}
	
	// Send chunk data immediately 
	resp := &RespFrame{
		Type:    "streaming_chunk",
		ReqID:   frame.ReqID,
		Status:  frame.Status,
		Headers: nil, // Headers only in start frame
		Body:    frame.Data,
	}
	
	// Send to waiter without removing it (streaming continues)
	select {
	case ch <- resp:
		log.Printf("SERVER STREAMING: Sent chunk %d to waiter | ReqID: %s", frame.ChunkIndex, frame.ReqID)
	default:
		log.Printf("SERVER STREAMING: Failed to send chunk (channel full) | ReqID: %s", frame.ReqID)
	}
	ac.respMu.Unlock()
}

// handleStreamingEnd processes the end of a streaming response
func (ac *agentConn) handleStreamingEnd(data []byte) {
	var frame ChunkedRespFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse streaming_end from agent %s: %v", ac.id, err)
		return
	}

	log.Printf("SERVER STREAMING: Stream ended | ReqID: %s | AgentID: %s | TotalChunks: %d", 
		frame.ReqID, ac.id, frame.TotalChunks)

	// Get the waiting HTTP response writer and remove it
	ac.respMu.Lock()
	ch, exists := ac.waiters[frame.ReqID]
	if exists {
		delete(ac.waiters, frame.ReqID)
	}
	ac.respMu.Unlock()

	if !exists {
		log.Printf("SERVER STREAMING: No waiter found for streaming end | ReqID: %s | AgentID: %s", 
			frame.ReqID, ac.id)
		return
	}
	
	// Send end signal
	resp := &RespFrame{
		Type:    "streaming_end",
		ReqID:   frame.ReqID,
		Status:  frame.Status,
		Headers: nil,
		Body:    []byte{}, // Empty body for end frame
	}
	
	// Send final response and close channel
	select {
	case ch <- resp:
		log.Printf("SERVER STREAMING: Sent streaming_end to waiter | ReqID: %s", frame.ReqID)
	default:
		log.Printf("SERVER STREAMING: Failed to send streaming_end (channel full) | ReqID: %s", frame.ReqID)
	}
	close(ch)
}

// getAgent retrieves an agent connection by ID
func getAgent(id string) *agentConn {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	return agents[id]
}

// WebSocket connection tracking
var (
	webSocketSessions = make(map[string]*WebSocketSession) // reqID -> session
	webSocketMutex    sync.RWMutex
)

type WebSocketSession struct {
	ReqID      string
	TunnelID   string
	ClientConn *websocket.Conn // Connection to client
	ServerConn *agentConn      // Connection to agent
	CreatedAt  time.Time
	Active     bool
}

// handleWebSocketUpgradeSuccess handles successful WebSocket upgrade from agent
func (ac *agentConn) handleWebSocketUpgradeSuccess(data []byte) {
	var resp RespFrame
	if err := json.Unmarshal(data, &resp); err != nil {
		log.Printf("Failed to parse WebSocket upgrade response from agent %s: %v", ac.id, err)
		return
	}

	log.Printf("SERVER WEBSOCKET: Upgrade successful from agent | AgentID: %s | ReqID: %s", 
		ac.id, resp.ReqID)

	// Find the waiting client connection and upgrade it
	ac.respMu.Lock()
	ch, exists := ac.waiters[resp.ReqID]
	if exists {
		delete(ac.waiters, resp.ReqID)
	}
	ac.respMu.Unlock()

	if exists {
		select {
		case ch <- &resp:
			log.Printf("SERVER WEBSOCKET: Sent upgrade success to waiter | ReqID: %s", resp.ReqID)
		case <-time.After(1 * time.Second):
			log.Printf("SERVER WEBSOCKET: Timeout sending upgrade response | ReqID: %s", resp.ReqID)
		}
	} else {
		log.Printf("SERVER WEBSOCKET: No waiter found for upgrade response | ReqID: %s", resp.ReqID)
	}
}

// handleWebSocketFrame handles WebSocket frames from agent to client
func (ac *agentConn) handleWebSocketFrame(data []byte) {
	var frame WebSocketFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse WebSocket frame from agent %s: %v", ac.id, err)
		return
	}

	webSocketMutex.RLock()
	session, exists := webSocketSessions[frame.ReqID]
	webSocketMutex.RUnlock()

	if !exists || !session.Active {
		log.Printf("SERVER WEBSOCKET: No active session found for frame | ReqID: %s", frame.ReqID)
		return
	}

	// Forward frame to client
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := session.ClientConn.Write(ctx, websocket.MessageType(frame.MessageType), frame.Data)
	if err != nil {
		log.Printf("SERVER WEBSOCKET: Error writing frame to client | ReqID: %s | Error: %v", 
			frame.ReqID, err)
		// Mark session as inactive
		webSocketMutex.Lock()
		session.Active = false
		webSocketMutex.Unlock()
		return
	}

	log.Printf("SERVER WEBSOCKET: Forwarded frame from agent to client | ReqID: %s | Type: %d | Size: %d bytes", 
		frame.ReqID, frame.MessageType, len(frame.Data))
}

// handleWebSocketClose handles WebSocket close from agent
func (ac *agentConn) handleWebSocketClose(data []byte) {
	var frame WebSocketFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse WebSocket close from agent %s: %v", ac.id, err)
		return
	}

	webSocketMutex.Lock()
	session, exists := webSocketSessions[frame.ReqID]
	if exists {
		session.Active = false
		delete(webSocketSessions, frame.ReqID)
	}
	webSocketMutex.Unlock()

	if exists && session.ClientConn != nil {
		log.Printf("SERVER WEBSOCKET: Closing client connection | ReqID: %s", frame.ReqID)
		session.ClientConn.Close(websocket.StatusNormalClosure, "Agent closed connection")
	}
}

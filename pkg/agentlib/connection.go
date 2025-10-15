package agentlib

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	crypto "tunnel.local/crypto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// performHandshakeNew handles the initial handshake to establish encryption
func (a *Agent) performHandshakeNew(ctx context.Context, conn *websocket.Conn) (*crypto.StreamCipher, error) {
	// Read handshake from server
	var handshake HandshakeFrame
	err := wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake: %w", err)
	}

	// Send handshake ACK
	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		return nil, fmt.Errorf("failed to send handshake ACK: %w", err)
	}

	// Create cipher
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	masterSecret := sha256.Sum256([]byte(a.Secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	return cipher, nil
}

// handleMessagesNew processes incoming messages from the server
func (a *Agent) handleMessagesNew(ctx context.Context, conn *websocket.Conn, cipher *crypto.StreamCipher) error {
	writeEncrypted := func(v any) error {
		data := mustJSONNew(v)
		encrypted, err := cipher.Encrypt(data)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
		return conn.Write(ctx, websocket.MessageBinary, encrypted)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read message from server
		_, data, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}

		// Decrypt message
		decrypted, err := cipher.Decrypt(data)
		if err != nil {
			log.Printf("Failed to decrypt message: %v", err)
			continue
		}

		// Parse message type
		var baseMsg map[string]interface{}
		if err := json.Unmarshal(decrypted, &baseMsg); err != nil {
			log.Printf("Failed to parse message: %v", err)
			continue
		}

		msgType, ok := baseMsg["type"].(string)
		if !ok {
			log.Printf("Message missing type field")
			continue
		}

		// Handle different message types by delegating to appropriate modules
		// CRITICAL: TCP messages must be processed sequentially to preserve ordering
		// (tcp_connect must complete before tcp_data, tcp_data before tcp_disconnect)
		switch msgType {
		case "req":
			go a.handleHTTPRequestNew(decrypted, writeEncrypted)
		case "tcp_connect":
			// Process TCP connect synchronously to ensure connection exists before data arrives
			a.handleTcpConnectNew(decrypted, writeEncrypted)
		case "tcp_data":
			// Process TCP data synchronously to maintain data ordering
			a.handleTcpDataNew(decrypted, writeEncrypted)
		case "tcp_disconnect":
			// Process TCP disconnect synchronously to ensure all data is sent first
			a.handleTcpDisconnectNew(decrypted, writeEncrypted)
		case "websocket_frame":
			go a.handleWebSocketFrameMessage(decrypted)
		case "websocket_close":
			go a.handleWebSocketCloseMessage(decrypted)
		case "ping":
			go a.handlePingNew(decrypted, writeEncrypted)
		default:
			log.Printf("Unknown message type: %s", msgType)
		}
	}
}

// handleHTTPRequestNew processes HTTP requests from the server (delegation)
func (a *Agent) handleHTTPRequestNew(data []byte, writeEncrypted func(v any) error) {
	var req ReqFrame
	if err := json.Unmarshal(data, &req); err != nil {
		log.Printf("Failed to parse request: %v", err)
		return
	}

	// Log debug information (delegated to debug.go)
	a.logDebugRequestNew(&req)

	// Check if this is a WebSocket upgrade request (delegated to websocket_handler.go)
	if a.isWebSocketUpgradeNew(&req) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		a.handleWebSocketUpgradeNew(ctx, &req, writeEncrypted)
		return
	}

	// Handle regular HTTP request (delegated to http_forwarder.go)
	a.forwardHTTPRequestNew(&req, writeEncrypted)
}

// handleWebSocketFrameMessage handles WebSocket frame forwarding (delegation)
func (a *Agent) handleWebSocketFrameMessage(data []byte) {
	var frame WebSocketFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse WebSocket frame: %v", err)
		return
	}
	a.handleWebSocketFrameNew(&frame)
}

// handleWebSocketCloseMessage handles WebSocket close from server (delegation)
func (a *Agent) handleWebSocketCloseMessage(data []byte) {
	var frame WebSocketFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse WebSocket close frame: %v", err)
		return
	}
	a.handleWebSocketCloseNew(&frame)
}

// handlePingNew responds to ping messages with pong (delegation)
func (a *Agent) handlePingNew(data []byte, writeEncrypted func(v any) error) {
	var ping PingFrame
	if err := json.Unmarshal(data, &ping); err != nil {
		log.Printf("Failed to parse ping frame: %v", err)
		return
	}

	// Respond with pong, echoing the timestamp and tunnel ID
	pong := &PongFrame{
		Type:      "pong",
		Timestamp: ping.Timestamp,
		TunnelID:  ping.TunnelID,
	}

	if err := writeEncrypted(pong); err != nil {
		log.Printf("Failed to send pong response: %v", err)
		return
	}

	log.Printf("Responded to ping from server | TunnelID: %s", ping.TunnelID)
}
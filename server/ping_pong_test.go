package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// TestWebSocketReadLimit tests that the WebSocket read limit is properly configured
func TestWebSocketReadLimit(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server
	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert to WebSocket URL
	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	// Complete handshake first
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		t.Fatalf("Failed to read handshake: %v", err)
	}

	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		t.Fatalf("Failed to send handshake ACK: %v", err)
	}

	// Create cipher
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	masterSecret := sha256.Sum256([]byte(secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Test sending a large message (within crypto limits)
	// Create a message that's about 10MB (within the 16MB crypto limit)
	largeData := make([]byte, 10*1024*1024) // 10MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}

	// Create a message with large data
	largeMessage := struct {
		TunnelInfoFrame
		LargeData []byte `json:"large_data"`
	}{
		TunnelInfoFrame: tunnelInfo,
		LargeData:       largeData,
	}

	messageJSON, err := json.Marshal(largeMessage)
	if err != nil {
		t.Fatalf("Failed to marshal large message: %v", err)
	}

	// This should succeed with the new 20MB limit
	encryptedData, err := cipher.Encrypt(messageJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt large message: %v", err)
	}

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send large encrypted message: %v", err)
	}

	// Give some time for the server to process
	time.Sleep(100 * time.Millisecond)

	// Verify the connection is still alive and the agent is registered
	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Error("Agent should still be registered after sending large message")
	}
	if agent != nil && agent.cipher == nil {
		t.Error("Agent cipher should be initialized")
	}
}

// TestHandlePing tests the server's ping message handling
func TestHandlePing(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server
	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert to WebSocket URL
	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	// Complete handshake
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		t.Fatalf("Failed to read handshake: %v", err)
	}

	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		t.Fatalf("Failed to send handshake ACK: %v", err)
	}

	// Create cipher
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	masterSecret := sha256.Sum256([]byte(secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Send tunnel info first
	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}

	tunnelInfoJSON, err := json.Marshal(tunnelInfo)
	if err != nil {
		t.Fatalf("Failed to marshal tunnel info: %v", err)
	}

	encryptedData, err := cipher.Encrypt(tunnelInfoJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt tunnel info: %v", err)
	}

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send tunnel info: %v", err)
	}

	time.Sleep(100 * time.Millisecond) // Let the server process

	// Now test ping functionality
	pingTime := time.Now()
	ping := PingFrame{
		Type:      "ping",
		Timestamp: pingTime,
	}

	pingJSON, err := json.Marshal(ping)
	if err != nil {
		t.Fatalf("Failed to marshal ping: %v", err)
	}

	encryptedPing, err := cipher.Encrypt(pingJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt ping: %v", err)
	}

	// Send ping to server
	err = conn.Write(ctx, websocket.MessageBinary, encryptedPing)
	if err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// Read pong response from server
	readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readCancel()

	_, responseData, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("Failed to read pong response: %v", err)
	}

	// Decrypt response
	decryptedResponse, err := cipher.Decrypt(responseData)
	if err != nil {
		t.Fatalf("Failed to decrypt pong response: %v", err)
	}

	var pong PongFrame
	err = json.Unmarshal(decryptedResponse, &pong)
	if err != nil {
		t.Fatalf("Failed to unmarshal pong: %v", err)
	}

	// Verify pong response
	if pong.Type != "pong" {
		t.Errorf("Expected pong type, got: %s", pong.Type)
	}

	if !pong.Timestamp.Equal(pingTime) {
		t.Errorf("Expected pong timestamp %v, got: %v", pingTime, pong.Timestamp)
	}
}

// TestPingRoutineTimeout tests the server's ping routine timeout behavior
func TestPingRoutineTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	tunnelID, secret := setupTestTunnel(t)

	// Create agent connection manually to test ping routine
	ac := &agentConn{
		id:               tunnelID,
		secret:           secret,
		waiters:          make(map[string]chan *RespFrame),
		tcpConns:         make(map[string]*TcpConn),
		chunkedResponses: make(map[string]*ChunkedResponse),
		lastPong:         time.Now().Add(-4 * time.Minute), // Set last pong to 4 minutes ago (past timeout)
		connectedAt:      time.Now(),
	}

	// Register the agent
	agentsMu.Lock()
	agents[tunnelID] = ac
	agentsMu.Unlock()

	// Create a mock WebSocket connection that will be closed when timeout is reached
	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	ac.ws = conn

	// Create a context that will be cancelled when connection should close
	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

	// Start the ping routine with the expired last pong time
	go ac.pingRoutine(connCtx)

	// Wait for a short period and check if the connection gets closed due to timeout
	select {
	case <-time.After(2 * time.Second):
		// The connection should close quickly due to expired lastPong
		// Try to read from the connection - it should fail if closed
		_, _, err := conn.Read(context.Background())
		if err == nil {
			t.Error("Expected connection to be closed due to ping timeout, but it remained open")
		}
	case <-connCtx.Done():
		// Context was cancelled, which is expected behavior
	}
}

// TestPingPongCycle tests a complete ping-pong cycle initiated by the server
func TestPingPongCycle(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server
	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert to WebSocket URL
	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	// Complete handshake
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		t.Fatalf("Failed to read handshake: %v", err)
	}

	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		t.Fatalf("Failed to send handshake ACK: %v", err)
	}

	// Create cipher
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	masterSecret := sha256.Sum256([]byte(secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Send tunnel info
	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}

	tunnelInfoJSON, err := json.Marshal(tunnelInfo)
	if err != nil {
		t.Fatalf("Failed to marshal tunnel info: %v", err)
	}

	encryptedData, err := cipher.Encrypt(tunnelInfoJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt tunnel info: %v", err)
	}

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send tunnel info: %v", err)
	}

	// Wait for server's ping (server sends ping every 30 seconds in production, but we'll wait less)
	// We'll simulate receiving a ping from the server by manually triggering it

	// Get the agent connection to test ping routine
	agentsMu.RLock()
	ac, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Fatal("Agent should be registered")
	}

	// Test the ping routine by calling it directly
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()

	// Store initial last pong time
	ac.pingMu.RLock()
	initialPong := ac.lastPong
	ac.pingMu.RUnlock()

	// Manually send a ping to test the cycle
	ping := &PingFrame{
		Type:      "ping",
		Timestamp: time.Now(),
	}

	err = ac.writeEncrypted(pingCtx, ping)
	if err != nil {
		t.Fatalf("Failed to send ping from server: %v", err)
	}

	// Read the ping message on client side and respond with pong
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	defer readCancel()

	_, responseData, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("Failed to read ping from server: %v", err)
	}

	// Decrypt ping
	decryptedPing, err := cipher.Decrypt(responseData)
	if err != nil {
		t.Fatalf("Failed to decrypt ping: %v", err)
	}

	var receivedPing PingFrame
	err = json.Unmarshal(decryptedPing, &receivedPing)
	if err != nil {
		t.Fatalf("Failed to unmarshal ping: %v", err)
	}

	if receivedPing.Type != "ping" {
		t.Errorf("Expected ping type, got: %s", receivedPing.Type)
	}

	// Send pong response
	pong := PongFrame{
		Type:      "pong",
		Timestamp: receivedPing.Timestamp,
	}

	pongJSON, err := json.Marshal(pong)
	if err != nil {
		t.Fatalf("Failed to marshal pong: %v", err)
	}

	encryptedPong, err := cipher.Encrypt(pongJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt pong: %v", err)
	}

	err = conn.Write(ctx, websocket.MessageBinary, encryptedPong)
	if err != nil {
		t.Fatalf("Failed to send pong: %v", err)
	}

	// Give server time to process pong
	time.Sleep(100 * time.Millisecond)

	// Verify that lastPong was updated
	ac.pingMu.RLock()
	updatedPong := ac.lastPong
	ac.pingMu.RUnlock()

	if !updatedPong.After(initialPong) {
		t.Error("Last pong time should be updated after receiving pong response")
	}
}

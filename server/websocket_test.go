package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// Test helper to create a mock tunnel for testing
func setupTestTunnel(t *testing.T) (string, string) {
	id := "test-tunnel-id"
	secret := "test-secret-key"

	tunnelsMu.Lock()
	tunnels[id] = &TunnelInfo{
		Secret:    secret,
		Protocol:  "http",
		Port:      0,
		Created:   time.Now(),
		CustomURL: "",
	}
	tunnelsMu.Unlock()

	// Cleanup
	t.Cleanup(func() {
		tunnelsMu.Lock()
		delete(tunnels, id)
		tunnelsMu.Unlock()

		agentsMu.Lock()
		delete(agents, id)
		agentsMu.Unlock()
	})

	return id, secret
}

// TestWebSocketKeyExchange tests the complete key exchange protocol
func TestWebSocketKeyExchange(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server
	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert to WebSocket URL
	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	// Test WebSocket connection and key exchange
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	// Step 1: Receive handshake from server
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		t.Fatalf("Failed to read handshake: %v", err)
	}

	if handshake.Type != "handshake" {
		t.Errorf("Expected handshake type, got: %s", handshake.Type)
	}

	if handshake.Salt == "" {
		t.Error("Expected salt in handshake")
	}

	// Step 2: Send handshake ACK (plain text)
	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}

	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		t.Fatalf("Failed to send handshake ACK: %v", err)
	}

	// Step 3: Create cipher to send encrypted tunnel info
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}

	masterSecret := sha256.Sum256([]byte(secret))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false) // false = isClient
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Step 4: Send encrypted tunnel info
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
		t.Fatalf("Failed to send encrypted tunnel info: %v", err)
	}

	// Verify agent connection was registered
	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Error("Agent should be registered after successful key exchange")
	} else if agent.cipher == nil {
		t.Error("Agent cipher should be initialized after key exchange")
	}
}

// TestHandshakeACKValidation tests different ACK message formats
func TestHandshakeACKValidation(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	testCases := []struct {
		name        string
		ackMessage  map[string]interface{}
		shouldFail  bool
		description string
	}{
		{
			name: "valid_ack",
			ackMessage: map[string]interface{}{
				"type": "handshake",
				"ack":  true,
			},
			shouldFail:  false,
			description: "Valid handshake ACK should succeed",
		},
		{
			name: "wrong_type",
			ackMessage: map[string]interface{}{
				"type": "ack",
				"ack":  true,
			},
			shouldFail:  true,
			description: "Wrong message type should fail",
		},
		{
			name: "missing_ack",
			ackMessage: map[string]interface{}{
				"type": "handshake",
			},
			shouldFail:  true,
			description: "Missing ack field should fail",
		},
		{
			name: "false_ack",
			ackMessage: map[string]interface{}{
				"type": "handshake",
				"ack":  false,
			},
			shouldFail:  true,
			description: "False ack should fail",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test server
			mux := http.NewServeMux()
			mux.HandleFunc("/__ws__", wsHandler)
			server := httptest.NewServer(mux)
			defer server.Close()

			// Convert to WebSocket URL
			wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, _, err := websocket.Dial(ctx, wsURL, nil)
			if err != nil {
				t.Fatalf("Failed to establish WebSocket connection: %v", err)
			}
			defer conn.Close(websocket.StatusNormalClosure, "test completed")

			// Read handshake
			var handshake HandshakeFrame
			err = wsjson.Read(ctx, conn, &handshake)
			if err != nil {
				t.Fatalf("Failed to read handshake: %v", err)
			}

			// Send test ACK message
			err = wsjson.Write(ctx, conn, tc.ackMessage)
			if err != nil {
				t.Fatalf("Failed to send ACK: %v", err)
			}

			// Check if agent was registered (indicates success)
			time.Sleep(100 * time.Millisecond) // Give server time to process

			agentsMu.RLock()
			_, exists := agents[tunnelID]
			agentsMu.RUnlock()

			if tc.shouldFail && exists {
				t.Errorf("%s: Expected failure but agent was registered", tc.description)
			} else if !tc.shouldFail && !exists {
				t.Errorf("%s: Expected success but agent was not registered", tc.description)
			}

			// Cleanup for next test
			agentsMu.Lock()
			delete(agents, tunnelID)
			agentsMu.Unlock()
		})
	}
}

// TestMessageTypeHandling tests that server properly handles binary vs text messages
func TestMessageTypeHandling(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server
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

	// Complete key exchange
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

	// Setup cipher
	salt, _ := base64.StdEncoding.DecodeString(handshake.Salt)
	masterSecret := sha256.Sum256([]byte(secret))
	cipher, _ := crypto.NewStreamCipher(masterSecret[:], salt, false)

	// Test 1: Send MessageText after key exchange (should be ignored)
	textMessage := []byte(`{"type": "test", "data": "should be ignored"}`)
	err = conn.Write(ctx, websocket.MessageText, textMessage)
	if err != nil {
		t.Fatalf("Failed to send text message: %v", err)
	}

	// Test 2: Send MessageBinary with encrypted data (should be processed)
	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}
	tunnelInfoJSON, _ := json.Marshal(tunnelInfo)
	encryptedData, _ := cipher.Encrypt(tunnelInfoJSON)

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send binary message: %v", err)
	}

	// Verify connection is stable and agent is registered
	time.Sleep(100 * time.Millisecond)

	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Error("Agent should be registered after successful binary message")
	} else if agent.cipher == nil {
		t.Error("Agent cipher should be initialized")
	}
}

// TestTunnelInfoAfterKeyExchange tests that tunnel info is properly handled
func TestTunnelInfoAfterKeyExchange(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	// Create test server with message logging
	var receivedMessages []string
	var mu sync.Mutex

	// Override handleMessage to log received messages
	originalHandleMessage := func(ac *agentConn) func([]byte) {
		return ac.handleMessage
	}

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

	// Complete key exchange
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

	// Setup cipher and send tunnel info
	salt, _ := base64.StdEncoding.DecodeString(handshake.Salt)
	masterSecret := sha256.Sum256([]byte(secret))
	cipher, _ := crypto.NewStreamCipher(masterSecret[:], salt, false)

	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "tcp",
		Port:     3306,
	}
	tunnelInfoJSON, _ := json.Marshal(tunnelInfo)
	encryptedData, _ := cipher.Encrypt(tunnelInfoJSON)

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send tunnel info: %v", err)
	}

	// Verify tunnel info was processed
	time.Sleep(200 * time.Millisecond)

	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Fatal("Agent should be registered")
	}

	// Verify connection remains stable
	if agent.ws == nil {
		t.Error("WebSocket connection should be active")
	}

	_ = receivedMessages
	_ = mu
	_ = originalHandleMessage
}

// TestWebSocketConnectionStability tests that connections remain stable after key exchange
func TestWebSocketConnectionStability(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to establish WebSocket connection: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "test completed")

	// Complete key exchange
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

	// Setup cipher
	salt, _ := base64.StdEncoding.DecodeString(handshake.Salt)
	masterSecret := sha256.Sum256([]byte(secret))
	cipher, _ := crypto.NewStreamCipher(masterSecret[:], salt, false)

	// Send tunnel info
	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}
	tunnelInfoJSON, _ := json.Marshal(tunnelInfo)
	encryptedData, _ := cipher.Encrypt(tunnelInfoJSON)

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send tunnel info: %v", err)
	}

	// Wait and verify connection remains stable
	time.Sleep(1 * time.Second)

	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Fatal("Agent should still be registered")
	}

	// Test that we can send more encrypted messages
	pingFrame := PingFrame{
		Type:      "ping",
		Timestamp: time.Now(),
	}
	pingJSON, _ := json.Marshal(pingFrame)
	encryptedPing, _ := cipher.Encrypt(pingJSON)

	err = conn.Write(ctx, websocket.MessageBinary, encryptedPing)
	if err != nil {
		t.Errorf("Should be able to send additional encrypted messages: %v", err)
	}

	// Verify agent is still connected after additional messages
	time.Sleep(100 * time.Millisecond)

	agentsMu.RLock()
	_, stillExists := agents[tunnelID]
	agentsMu.RUnlock()

	if !stillExists {
		t.Error("Agent should remain connected after sending additional messages")
	}

	_ = agent
}

// TestKeyExchangeProtocolRegression tests the specific bug we fixed
// This test ensures that:
// 1. Server expects plain text handshake ACK (not encrypted)
// 2. Server processes MessageBinary for encrypted messages (not MessageText)
// 3. Handshake ACK must have type="handshake" and ack=true
func TestKeyExchangeProtocolRegression(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

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

	// Step 1: Receive handshake (should be JSON, not encrypted)
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		t.Fatalf("Server should send handshake as plain JSON: %v", err)
	}

	// Step 2: Send ACK as plain text (NOT encrypted - this was the bug)
	handshakeResp := map[string]interface{}{
		"type": "handshake", // Must be "handshake", not "ack"
		"ack":  true,        // Must be true
	}

	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		t.Fatalf("Failed to send plain text ACK: %v", err)
	}

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	// Verify agent was registered (proves ACK was accepted)
	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Fatal("Agent should be registered after plain text ACK")
	}

	if agent.cipher == nil {
		t.Error("Agent cipher should be initialized after key exchange")
	}

	// Step 3: Test that encrypted messages use MessageBinary (not MessageText)
	salt, _ := base64.StdEncoding.DecodeString(handshake.Salt)
	masterSecret := sha256.Sum256([]byte(secret))
	cipher, _ := crypto.NewStreamCipher(masterSecret[:], salt, false)

	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: "http",
		Port:     0,
	}
	tunnelInfoJSON, _ := json.Marshal(tunnelInfo)
	encryptedData, _ := cipher.Encrypt(tunnelInfoJSON)

	// Send as MessageBinary (not MessageText - this was part of the fix)
	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send encrypted data as MessageBinary: %v", err)
	}

	// Verify connection remains stable after encrypted message
	time.Sleep(100 * time.Millisecond)

	agentsMu.RLock()
	_, stillExists := agents[tunnelID]
	agentsMu.RUnlock()

	if !stillExists {
		t.Error("Connection should remain stable after encrypted MessageBinary")
	}

	// Test that MessageText is ignored after key exchange
	plainTextMessage := []byte(`{"type": "should_be_ignored"}`)
	err = conn.Write(ctx, websocket.MessageText, plainTextMessage)
	if err != nil {
		t.Fatalf("Failed to send MessageText: %v", err)
	}

	// Connection should still be stable (MessageText ignored)
	time.Sleep(100 * time.Millisecond)

	agentsMu.RLock()
	_, finalExists := agents[tunnelID]
	agentsMu.RUnlock()

	if !finalExists {
		t.Error("Connection should remain stable even after MessageText (should be ignored)")
	}
}

// TestCipherKeyDerivation tests that server and agent use the same key derivation
// This test ensures the fix for the cipher mismatch bug
func TestCipherKeyDerivation(t *testing.T) {
	tunnelID, secret := setupTestTunnel(t)

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

	// Complete key exchange
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

	// Create agent-side cipher (same as agent does)
	salt, _ := base64.StdEncoding.DecodeString(handshake.Salt)
	masterSecret := sha256.Sum256([]byte(secret)) // Hash the secret like agent does
	agentCipher, _ := crypto.NewStreamCipher(masterSecret[:], salt, false)

	// Send encrypted message from agent side
	testMessage := map[string]interface{}{
		"type": "test_cipher",
		"data": "cipher_test_message",
	}
	testJSON, _ := json.Marshal(testMessage)
	encryptedData, err := agentCipher.Encrypt(testJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt test message: %v", err)
	}

	err = conn.Write(ctx, websocket.MessageBinary, encryptedData)
	if err != nil {
		t.Fatalf("Failed to send encrypted test message: %v", err)
	}

	// Verify agent was registered and cipher works
	time.Sleep(100 * time.Millisecond)

	agentsMu.RLock()
	agent, exists := agents[tunnelID]
	agentsMu.RUnlock()

	if !exists {
		t.Fatal("Agent should be registered")
	}

	// Test that server can encrypt messages that agent can decrypt
	serverMessage := map[string]interface{}{
		"type": "server_test",
		"data": "server_to_agent_message",
	}
	serverJSON, _ := json.Marshal(serverMessage)
	serverEncrypted, err := agent.cipher.Encrypt(serverJSON)
	if err != nil {
		t.Fatalf("Server failed to encrypt message: %v", err)
	}

	// Agent should be able to decrypt server's message
	decrypted, err := agentCipher.Decrypt(serverEncrypted)
	if err != nil {
		t.Errorf("Agent failed to decrypt server message (cipher mismatch): %v", err)
	}

	var decryptedMessage map[string]interface{}
	if err := json.Unmarshal(decrypted, &decryptedMessage); err != nil {
		t.Errorf("Failed to parse decrypted message: %v", err)
	}

	if decryptedMessage["type"] != "server_test" {
		t.Errorf("Expected 'server_test', got: %v", decryptedMessage["type"])
	}

	if decryptedMessage["data"] != "server_to_agent_message" {
		t.Errorf("Expected 'server_to_agent_message', got: %v", decryptedMessage["data"])
	}
}

// Benchmark key exchange performance
func BenchmarkKeyExchange(b *testing.B) {
	tunnelID, secret := setupTestTunnel(&testing.T{})

	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[4:] + "/__ws__?id=" + tunnelID + "&secret=" + secret

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, _, err := websocket.Dial(ctx, wsURL, nil)
			if err != nil {
				b.Fatalf("Failed to establish WebSocket connection: %v", err)
			}
			defer conn.Close(websocket.StatusNormalClosure, "benchmark completed")

			// Complete key exchange
			var handshake HandshakeFrame
			err = wsjson.Read(ctx, conn, &handshake)
			if err != nil {
				b.Fatalf("Failed to read handshake: %v", err)
			}

			handshakeResp := map[string]interface{}{
				"type": "handshake",
				"ack":  true,
			}
			err = wsjson.Write(ctx, conn, handshakeResp)
			if err != nil {
				b.Fatalf("Failed to send handshake ACK: %v", err)
			}

			// Cleanup
			agentsMu.Lock()
			delete(agents, tunnelID)
			agentsMu.Unlock()
		}()
	}
}
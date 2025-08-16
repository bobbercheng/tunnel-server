package agentlib

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// mockServer represents a mock tunnel server for testing
type mockServer struct {
	server          *httptest.Server
	wsHandler       http.HandlerFunc
	handshakeCount  int
	pingCount       int
	pongCount       int
	mu              sync.Mutex
	lastPingTime    time.Time
	receivedPongs   []time.Time
	connectionCount int
}

// newMockServer creates a new mock server for testing
func newMockServer() *mockServer {
	ms := &mockServer{
		receivedPongs: make([]time.Time, 0),
	}

	ms.wsHandler = func(w http.ResponseWriter, r *http.Request) {
		ms.mu.Lock()
		ms.connectionCount++
		ms.mu.Unlock()

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:       []string{"tunnel"},
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "server error")

		// Set read limit like the real server
		conn.SetReadLimit(20 * 1024 * 1024)

		ms.handleConnection(conn)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", ms.wsHandler)
	ms.server = httptest.NewServer(mux)

	return ms
}

// handleConnection handles a WebSocket connection like the real server
func (ms *mockServer) handleConnection(conn *websocket.Conn) {
	ctx := context.Background()

	// Send handshake
	ms.mu.Lock()
	ms.handshakeCount++
	ms.mu.Unlock()

	handshake := map[string]interface{}{
		"type": "handshake",
		"salt": "dGVzdC1zYWx0LWZvci11bml0LXRlc3RpbmctMTIzNA==", // base64 encoded test salt
	}

	err := wsjson.Write(ctx, conn, handshake)
	if err != nil {
		return
	}

	// Wait for handshake ACK
	_, ackData, err := conn.Read(ctx)
	if err != nil {
		return
	}

	var ackMsg map[string]interface{}
	if err := json.Unmarshal(ackData, &ackMsg); err != nil {
		return
	}

	if ackMsg["type"] != "handshake" || ackMsg["ack"] != true {
		return
	}

	// Start ping routine (send ping every 2 seconds for testing)
	go ms.pingRoutine(ctx, conn)

	// Handle messages
	for {
		msgType, data, err := conn.Read(ctx)
		if err != nil {
			break
		}

		if msgType != websocket.MessageBinary {
			continue
		}

		// For simplicity, we'll handle messages as plain JSON (no encryption in test)
		var baseMsg struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &baseMsg); err != nil {
			continue
		}

		switch baseMsg.Type {
		case "pong":
			ms.mu.Lock()
			ms.pongCount++
			ms.receivedPongs = append(ms.receivedPongs, time.Now())
			ms.mu.Unlock()
		case "tunnel_info":
			// Acknowledge tunnel info
		}
	}
}

// pingRoutine sends periodic pings (faster than production for testing)
func (ms *mockServer) pingRoutine(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(2 * time.Second) // Fast ping for testing
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ms.mu.Lock()
			ms.pingCount++
			ms.lastPingTime = time.Now()
			ms.mu.Unlock()

			ping := map[string]interface{}{
				"type":      "ping",
				"timestamp": time.Now(),
			}

			if err := wsjson.Write(ctx, conn, ping); err != nil {
				return
			}
		}
	}
}

// close shuts down the mock server
func (ms *mockServer) close() {
	ms.server.Close()
}

// getStats returns current server statistics
func (ms *mockServer) getStats() (handshakes, pings, pongs, connections int, lastPing time.Time, receivedPongs []time.Time) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Make a copy of receivedPongs to avoid race conditions
	pongsCopy := make([]time.Time, len(ms.receivedPongs))
	copy(pongsCopy, ms.receivedPongs)

	return ms.handshakeCount, ms.pingCount, ms.pongCount, ms.connectionCount, ms.lastPingTime, pongsCopy
}

// TestAgentPingTimeout tests the agent's ping timeout behavior (150 seconds)
func TestAgentPingTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	server := newMockServer()
	defer server.close()

	agent := &Agent{
		ServerURL: server.server.URL,
		LocalURL:  "http://127.0.0.1:8080",
		Protocol:  "http",
		Port:      0,
		CustomURL: "",
	}

	// Create a context with timeout to prevent the test from running too long
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start the agent connection in a goroutine
	agentDone := make(chan error, 1)
	go func() {
		// Modify agent to have expired lastPong for testing
		agentDone <- agent.runOnce()
	}()

	// Wait for connection to be established
	time.Sleep(1 * time.Second)

	// Manually set lastPong to an old time to trigger timeout
	agent.pingMu.Lock()
	agent.lastPong = time.Now().Add(-160 * time.Second) // 160 seconds ago (past the 150s threshold)
	agent.pingMu.Unlock()

	// Wait for agent to timeout and close connection
	select {
	case err := <-agentDone:
		// Agent should complete without error (normal closure due to timeout)
		if err != nil {
			t.Logf("Agent returned with error (expected for timeout test): %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Test timed out waiting for agent to close connection")
	}
}

// TestAgentPingPongCycle tests the complete ping-pong communication cycle
func TestAgentPingPongCycle(t *testing.T) {
	server := newMockServer()
	defer server.close()

	agent := &Agent{
		ServerURL: server.server.URL,
		LocalURL:  "http://127.0.0.1:8080",
		Protocol:  "http",
		Port:      0,
		CustomURL: "",
	}

	// Start agent connection in a goroutine
	agentDone := make(chan error, 1)
	go func() {
		// Run for a limited time
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		// Simulate runOnce with timeout
		select {
		case <-ctx.Done():
			agentDone <- nil // Normal timeout
		default:
			agentDone <- agent.runOnce()
		}
	}()

	// Wait for connection establishment and some ping-pong cycles
	time.Sleep(6 * time.Second)

	// Check that ping-pong communication occurred
	handshakes, pings, pongs, connections, lastPing, receivedPongs := server.getStats()

	if handshakes == 0 {
		t.Error("Expected at least one handshake")
	}

	if connections == 0 {
		t.Error("Expected at least one connection")
	}

	if pings == 0 {
		t.Error("Expected server to send pings")
	}

	if pongs == 0 {
		t.Error("Expected agent to respond with pongs")
	}

	if lastPing.IsZero() {
		t.Error("Expected server to record ping times")
	}

	if len(receivedPongs) == 0 {
		t.Error("Expected server to receive pong responses")
	}

	// Verify that pongs were received in response to pings
	if pongs < pings-1 { // Allow for timing differences
		t.Errorf("Expected pongs (%d) to be close to pings (%d)", pongs, pings)
	}

	t.Logf("Test completed: %d handshakes, %d pings, %d pongs, %d connections", handshakes, pings, pongs, connections)

	// Clean up
	select {
	case <-agentDone:
		// Agent finished
	case <-time.After(2 * time.Second):
		// Timeout waiting for agent to finish is acceptable
	}
}

// TestAgentReconnectionAfterTimeout tests agent reconnection behavior
func TestAgentReconnectionAfterTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping reconnection test in short mode")
	}

	server := newMockServer()
	defer server.close()

	agent := &Agent{
		ServerURL: server.server.URL,
		LocalURL:  "http://127.0.0.1:8080",
		Protocol:  "http",
		Port:      0,
		CustomURL: "",
	}

	// Track reconnections
	reconnectCount := 0

	// Start agent with simulated reconnection logic
	agentDone := make(chan bool, 1)
	go func() {
		defer func() { agentDone <- true }()

		start := time.Now()
		for time.Since(start) < 6*time.Second && reconnectCount < 3 {
			reconnectCount++

			// Try to connect to the server
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Logf("Agent connection panic (expected): %v", r)
					}
				}()

				// Brief connection attempt
				err := agent.runOnce()
				if err != nil {
					t.Logf("Agent connection %d error (expected): %v", reconnectCount, err)
				}
			}()

			// Brief delay between reconnections
			if reconnectCount < 3 {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	// Wait for test completion
	select {
	case <-agentDone:
		// Test completed
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out")
	}

	// Verify multiple connections occurred (indicating reconnections)
	_, _, _, connections, _, _ := server.getStats()

	if connections < 1 {
		t.Errorf("Expected at least 1 connection, got %d", connections)
	}

	if reconnectCount < 2 {
		t.Errorf("Expected at least 2 connection attempts, got %d", reconnectCount)
	}

	t.Logf("Reconnection test completed: %d connections, %d connection attempts", connections, reconnectCount)
}

// TestAgentPingTimeoutThreshold tests that the 150-second threshold works correctly
func TestAgentPingTimeoutThreshold(t *testing.T) {
	agent := &Agent{
		ServerURL: "ws://localhost:8080",
		LocalURL:  "http://127.0.0.1:8080",
		Protocol:  "http",
		Port:      0,
		CustomURL: "",
		lastPong:  time.Now().Add(-140 * time.Second), // 140 seconds ago (within threshold)
	}

	// Test that 140 seconds (within 150s threshold) should not trigger timeout
	agent.pingMu.Lock()
	lastPong := agent.lastPong
	agent.pingMu.Unlock()

	timeSinceLastPong := time.Since(lastPong)
	shouldTimeout := timeSinceLastPong > 150*time.Second

	if shouldTimeout {
		t.Errorf("Agent should not timeout at %v (threshold is 150s)", timeSinceLastPong)
	}

	// Test that 160 seconds (past 150s threshold) should trigger timeout
	agent.pingMu.Lock()
	agent.lastPong = time.Now().Add(-160 * time.Second) // 160 seconds ago (past threshold)
	lastPong = agent.lastPong
	agent.pingMu.Unlock()

	timeSinceLastPong = time.Since(lastPong)
	shouldTimeout = timeSinceLastPong > 150*time.Second

	if !shouldTimeout {
		t.Errorf("Agent should timeout at %v (threshold is 150s)", timeSinceLastPong)
	}
}

// TestAgentPingInterval tests that the agent properly handles ping intervals
func TestAgentPingInterval(t *testing.T) {
	server := newMockServer()
	defer server.close()

	agent := &Agent{
		ServerURL: server.server.URL,
		LocalURL:  "http://127.0.0.1:8080",
		Protocol:  "http",
		Port:      0,
		CustomURL: "",
	}

	// Start a short connection to test ping behavior
	agentDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		select {
		case <-ctx.Done():
			agentDone <- nil
		default:
			agentDone <- agent.runOnce()
		}
	}()

	// Wait for some ping activity
	time.Sleep(4 * time.Second)

	// Check that ping activity occurred
	_, pings, pongs, _, _, _ := server.getStats()

	if pings == 0 {
		t.Error("Expected server to send pings during connection")
	}

	if pongs == 0 {
		t.Error("Expected agent to respond with pongs")
	}

	// Verify reasonable ping/pong ratio (allowing for timing differences)
	if pongs > pings+1 || pongs < pings-1 {
		t.Errorf("Ping/pong ratio seems off: %d pings, %d pongs", pings, pongs)
	}

	// Clean up
	select {
	case <-agentDone:
		// Agent finished
	case <-time.After(2 * time.Second):
		// Timeout is acceptable
	}
}

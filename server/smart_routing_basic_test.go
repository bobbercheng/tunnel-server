package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestExtractTunnelFromReferer tests the referer-based tunnel ID extraction
func TestExtractTunnelFromReferer(t *testing.T) {
	tests := []struct {
		name     string
		referer  string
		expected string
	}{
		{
			name:     "Valid referer with tunnel ID",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/__pub__/534a9143-cd73-4986-aa1d-35ef4fbde150/",
			expected: "534a9143-cd73-4986-aa1d-35ef4fbde150",
		},
		{
			name:     "Valid referer with path after tunnel ID",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/__pub__/534a9143-cd73-4986-aa1d-35ef4fbde150/some/page",
			expected: "534a9143-cd73-4986-aa1d-35ef4fbde150",
		},
		{
			name:     "Invalid referer - no __pub__ path",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/__register__",
			expected: "",
		},
		{
			name:     "Empty referer",
			referer:  "",
			expected: "",
		},
		{
			name:     "Invalid URL",
			referer:  "not-a-valid-url",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{
					"Referer": []string{tt.referer},
				},
			}
			result := extractTunnelFromReferer(req)
			if result != tt.expected {
				t.Errorf("extractTunnelFromReferer(%q) = %q, want %q", tt.referer, result, tt.expected)
			}
		})
	}
}

// TestGetActiveTunnelIDs tests active tunnel ID retrieval
func TestGetActiveTunnelIDs(t *testing.T) {
	// Clear agents for clean test
	agentsMu.Lock()
	originalAgents := agents
	agents = make(map[string]*agentConn)
	agentsMu.Unlock()

	// Restore original agents after test
	defer func() {
		agentsMu.Lock()
		agents = originalAgents
		agentsMu.Unlock()
	}()

	// Test with no agents
	tunnelIDs := getActiveTunnelIDs()
	if len(tunnelIDs) != 0 {
		t.Errorf("Expected 0 tunnel IDs, got %d", len(tunnelIDs))
	}

	// Add mock agents
	agentsMu.Lock()
	agents["tunnel-1"] = &agentConn{id: "tunnel-1"}
	agents["tunnel-2"] = &agentConn{id: "tunnel-2"}
	agentsMu.Unlock()

	tunnelIDs = getActiveTunnelIDs()
	if len(tunnelIDs) != 2 {
		t.Errorf("Expected 2 tunnel IDs, got %d", len(tunnelIDs))
	}

	// Verify tunnel IDs are present (order doesn't matter)
	expectedTunnels := map[string]bool{
		"tunnel-1": false,
		"tunnel-2": false,
	}

	for _, id := range tunnelIDs {
		if _, exists := expectedTunnels[id]; exists {
			expectedTunnels[id] = true
		} else {
			t.Errorf("Unexpected tunnel ID: %s", id)
		}
	}

	for id, found := range expectedTunnels {
		if !found {
			t.Errorf("Expected tunnel ID %s not found", id)
		}
	}
}

// TestExtractRealClientIP tests client IP extraction from various headers
func TestExtractRealClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remoteIP string
		expected string
	}{
		{
			name: "CF-Connecting-IP header (highest priority)",
			headers: map[string]string{
				"CF-Connecting-IP": "1.2.3.4",
				"X-Real-IP":        "5.6.7.8",
				"X-Forwarded-For":  "9.10.11.12",
			},
			remoteIP: "127.0.0.1:8080",
			expected: "1.2.3.4",
		},
		{
			name: "X-Real-IP header",
			headers: map[string]string{
				"X-Real-IP":       "5.6.7.8",
				"X-Forwarded-For": "9.10.11.12",
			},
			remoteIP: "127.0.0.1:8080",
			expected: "5.6.7.8",
		},
		{
			name: "X-Forwarded-For header (first IP)",
			headers: map[string]string{
				"X-Forwarded-For": "9.10.11.12, 13.14.15.16, 17.18.19.20",
			},
			remoteIP: "127.0.0.1:8080",
			expected: "9.10.11.12",
		},
		{
			name:     "No headers - use RemoteAddr",
			headers:  map[string]string{},
			remoteIP: "21.22.23.24:8080",
			expected: "21.22.23.24",
		},
		{
			name:     "Invalid RemoteAddr format",
			headers:  map[string]string{},
			remoteIP: "invalid-remote-addr",
			expected: "invalid-remote-addr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			req.RemoteAddr = tt.remoteIP

			result := extractRealClientIP(req)
			if result != tt.expected {
				t.Errorf("extractRealClientIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestIsAuthCookie tests authentication cookie detection
func TestIsAuthCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		expected   bool
	}{
		{"Auth cookie", "auth_token", true},
		{"Session cookie", "session_id", true},
		{"JWT cookie", "jwt_token", true},
		{"User cookie", "user_data", true},
		{"Bearer cookie", "bearer_token", true},
		{"Login cookie", "login_status", true},
		{"Regular cookie", "preferences", false},
		{"Theme cookie", "dark_mode", false},
		{"Empty name", "", false},
		{"Contains auth substring", "authentic", true}, // Should match because contains "auth"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAuthCookie(tt.cookieName)
			if result != tt.expected {
				t.Errorf("isAuthCookie(%q) = %v, want %v", tt.cookieName, result, tt.expected)
			}
		})
	}
}

// TestGenerateClientKey tests client key generation
func TestGenerateClientKey(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	req1.Header.Set("X-Forwarded-For", "1.2.3.4")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("User-Agent", "Chrome/100.0")
	req3.Header.Set("X-Forwarded-For", "5.6.7.8")

	key1 := generateClientKey(req1)
	key2 := generateClientKey(req2)
	key3 := generateClientKey(req3)

	// Same request should generate same key
	if key1 != key2 {
		t.Errorf("Same request should generate same client key")
	}

	// Different request should generate different key
	if key1 == key3 {
		t.Errorf("Different requests should generate different client keys")
	}

	// Keys should not be empty
	if key1 == "" || key3 == "" {
		t.Errorf("Client keys should not be empty")
	}

	// Keys should have reasonable length (hash-based)
	if len(key1) < 16 || len(key3) < 16 {
		t.Errorf("Client keys should have reasonable length, got %d and %d", len(key1), len(key3))
	}
}

// TestClientTrackerOperations tests basic client tracker functionality
func TestClientTrackerOperations(t *testing.T) {
	// Create a fresh tracker for testing
	tracker := NewClientTracker()
	
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Test-Agent")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	
	clientKey := tracker.TrackClient(req)
	if clientKey == "" {
		t.Fatal("Expected non-empty client key")
	}
	
	// Test initial state - no tunnel mapping
	tunnelID := tracker.GetBestTunnel(clientKey)
	if tunnelID != "" {
		t.Errorf("Expected empty tunnel for new client, got %s", tunnelID)
	}
	
	// Test learning mapping
	testTunnelID := "test-tunnel-123"
	tracker.LearnMapping(clientKey, testTunnelID)
	
	tunnelID = tracker.GetBestTunnel(clientKey)
	if tunnelID != testTunnelID {
		t.Errorf("Expected tunnel %s, got %s", testTunnelID, tunnelID)
	}
	
	// Test confidence
	confidence := tracker.GetConfidence(clientKey, testTunnelID)
	if confidence <= 0 {
		t.Errorf("Expected positive confidence, got %f", confidence)
	}
	
	// Test success recording
	tracker.RecordSuccess(clientKey, testTunnelID)
	
	newConfidence := tracker.GetConfidence(clientKey, testTunnelID)
	if newConfidence <= confidence {
		t.Errorf("Expected confidence to increase after success, got %f vs %f", newConfidence, confidence)
	}
	
	// Test failure recording
	tracker.RecordFailure(clientKey, testTunnelID)
	
	postFailureConfidence := tracker.GetConfidence(clientKey, testTunnelID)
	if postFailureConfidence >= newConfidence {
		t.Errorf("Expected confidence to decrease after failure, got %f vs %f", postFailureConfidence, newConfidence)
	}
}

// TestSmartRoutingIntegration tests integration with smart routing functions
func TestSmartRoutingIntegration(t *testing.T) {
	// Test asset detection
	assetPaths := []string{"/assets/app.js", "/static/style.css", "/favicon.ico"}
	for _, path := range assetPaths {
		if !isAssetRequest(path) {
			t.Errorf("Expected %s to be detected as asset", path)
		}
	}
	
	nonAssetPaths := []string{"/", "/api/users", "/about"}
	for _, path := range nonAssetPaths {
		if isAssetRequest(path) {
			t.Errorf("Expected %s to NOT be detected as asset", path)
		}
	}
	
	// Test API detection
	apiPaths := []string{"/api/users", "/v1/data", "/health"}
	for _, path := range apiPaths {
		if !isAPIRequest(path) {
			t.Errorf("Expected %s to be detected as API", path)
		}
	}
	
	nonAPIPaths := []string{"/", "/assets/app.js", "/about"}
	for _, path := range nonAPIPaths {
		if isAPIRequest(path) {
			t.Errorf("Expected %s to NOT be detected as API", path)
		}
	}
}
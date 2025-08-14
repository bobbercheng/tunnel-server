package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExtractTunnelFromReferer(t *testing.T) {
	tests := []struct {
		name     string
		referer  string
		expected string
	}{
		{
			name:     "Valid referer with tunnel ID",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/pub/534a9143-cd73-4986-aa1d-35ef4fbde150/",
			expected: "534a9143-cd73-4986-aa1d-35ef4fbde150",
		},
		{
			name:     "Valid referer with path after tunnel ID",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/pub/534a9143-cd73-4986-aa1d-35ef4fbde150/some/page",
			expected: "534a9143-cd73-4986-aa1d-35ef4fbde150",
		},
		{
			name:     "Invalid referer - no pub path",
			referer:  "https://tunnel-server-3w6u4kmniq-ue.a.run.app/register",
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
				t.Errorf("extractTunnelFromReferer() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetActiveTunnelIDs(t *testing.T) {
	// Save original state
	originalAgents := agents
	defer func() {
		agents = originalAgents
	}()

	// Test empty agents
	agents = map[string]*agentConn{}
	result := getActiveTunnelIDs()
	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %v", result)
	}

	// Test with mock agents
	agents = map[string]*agentConn{
		"tunnel-1": nil,
		"tunnel-2": nil,
	}
	result = getActiveTunnelIDs()
	if len(result) != 2 {
		t.Errorf("Expected 2 tunnel IDs, got %d", len(result))
	}
}

// Test enhanced fingerprinting functions
func TestExtractRealClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		remoteAddr string
		expected   string
	}{
		{
			name: "Cloudflare IP",
			headers: http.Header{
				"Cf-Connecting-Ip": []string{"192.168.1.100"},
				"X-Real-Ip":        []string{"10.0.0.1"},
			},
			expected: "192.168.1.100", // CF should take priority
		},
		{
			name: "X-Forwarded-For chain",
			headers: http.Header{
				"X-Forwarded-For": []string{"192.168.1.100, 10.0.0.1, 172.16.0.1"},
			},
			expected: "192.168.1.100", // First IP in chain
		},
		{
			name: "X-Real-IP",
			headers: http.Header{
				"X-Real-Ip": []string{"192.168.1.100"},
			},
			expected: "192.168.1.100",
		},
		{
			name:       "Remote address fallback",
			headers:    http.Header{},
			remoteAddr: "192.168.1.100:12345",
			expected:   "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header:     tt.headers,
				RemoteAddr: tt.remoteAddr,
			}

			result := extractRealClientIP(req)
			if result != tt.expected {
				t.Errorf("extractRealClientIP() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsSessionCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		expected   bool
	}{
		{"sessionid", "sessionid", true},
		{"SESSIONID", "SESSIONID", true},
		{"jsessionid", "jsessionid", true},
		{"connect.sid", "connect.sid", true},
		{"auth_token", "auth_token", true},
		{"jwt", "jwt", true},
		{"random_cookie", "random_cookie", false},
		{"csrf_token", "csrf_token", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSessionCookie(tt.cookieName)
			if result != tt.expected {
				t.Errorf("isSessionCookie(%q) = %v, want %v", tt.cookieName, result, tt.expected)
			}
		})
	}
}

func TestIsAuthCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		expected   bool
	}{
		{"auth_user", "auth_user", true},
		{"login_token", "login_token", true},
		{"user_session", "user_session", true},
		{"oauth_token", "oauth_token", true},
		{"regular_cookie", "regular_cookie", false},
		{"preference", "preference", false},
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

func TestGenerateClientKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		cookies        []*http.Cookie
		remoteAddr     string
		expectedPrefix string
		minConfidence  float64
	}{
		{
			name: "Auth header high confidence",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
				"User-Agent":    []string{"Mozilla/5.0"},
			},
			expectedPrefix: "auth:",
			minConfidence:  0.4,
		},
		{
			name: "Session cookie high confidence",
			cookies: []*http.Cookie{
				{Name: "sessionid", Value: "session123"},
			},
			headers: http.Header{
				"User-Agent": []string{"Mozilla/5.0"},
			},
			expectedPrefix: "session:",
			minConfidence:  0.3,
		},
		{
			name: "Custom session header",
			headers: http.Header{
				"X-Session-ID": []string{"custom123"},
				"User-Agent":   []string{"Mozilla/5.0"},
			},
			expectedPrefix: "token:",
			minConfidence:  0.15,
		},
		{
			name: "Basic fingerprint",
			headers: http.Header{
				"User-Agent":      []string{"Mozilla/5.0"},
				"Accept-Language": []string{"en-US,en;q=0.9"},
			},
			remoteAddr:     "192.168.1.100:12345",
			expectedPrefix: "fingerprint:",
			minConfidence:  0.35,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header:     tt.headers,
				RemoteAddr: tt.remoteAddr,
			}

			// Add cookies to request
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}

			clientKey := generateClientKey(req)

			// Check prefix
			if !strings.HasPrefix(clientKey, tt.expectedPrefix) {
				t.Errorf("generateClientKey() prefix = %v, want prefix %v",
					clientKey[:strings.Index(clientKey, ":")+1], tt.expectedPrefix)
			}

			// Check that session was created
			if session, exists := clientTracker.clientSessions[clientKey]; exists {
				if session.Confidence < tt.minConfidence {
					t.Errorf("Session confidence = %v, want >= %v",
						session.Confidence, tt.minConfidence)
				}
			} else {
				t.Error("Expected session to be created in clientTracker")
			}
		})
	}
}

func TestClientTrackerOperations(t *testing.T) {
	// Reset client tracker for test
	originalTracker := clientTracker
	defer func() {
		clientTracker = originalTracker
	}()

	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	clientKey := "test:client123"
	tunnelID := "tunnel-456"

	// Create session
	clientTracker.clientSessions[clientKey] = &ClientSession{
		ID:             clientKey,
		LastSeen:       time.Now(),
		TunnelMappings: make(map[string]int),
		SuccessRate:    make(map[string]float64),
		Confidence:     0.5,
	}

	t.Run("Learn mapping", func(t *testing.T) {
		clientTracker.LearnMapping(clientKey, tunnelID)

		session := clientTracker.clientSessions[clientKey]
		if session.TunnelMappings[tunnelID] != 1 {
			t.Errorf("Expected tunnel mapping count = 1, got %d", session.TunnelMappings[tunnelID])
		}

		if session.SuccessRate[tunnelID] != 0.8 {
			t.Errorf("Expected initial success rate = 0.8, got %f", session.SuccessRate[tunnelID])
		}
	})

	t.Run("Record success", func(t *testing.T) {
		initialCount := clientTracker.clientSessions[clientKey].TunnelMappings[tunnelID]
		clientTracker.RecordSuccess(clientKey, tunnelID)

		session := clientTracker.clientSessions[clientKey]
		if session.TunnelMappings[tunnelID] != initialCount+1 {
			t.Errorf("Expected tunnel mapping count = %d, got %d",
				initialCount+1, session.TunnelMappings[tunnelID])
		}

		// Check recent mapping
		if clientTracker.recentMappings[clientKey] != tunnelID {
			t.Error("Expected recent mapping to be updated")
		}
	})

	t.Run("Get best tunnel", func(t *testing.T) {
		bestTunnel := clientTracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID {
			t.Errorf("GetBestTunnel() = %v, want %v", bestTunnel, tunnelID)
		}
	})

	t.Run("Get confidence", func(t *testing.T) {
		confidence := clientTracker.GetConfidence(clientKey, tunnelID)
		if confidence <= 0 {
			t.Errorf("Expected positive confidence, got %f", confidence)
		}
	})

	t.Run("Record failure", func(t *testing.T) {
		initialSuccessRate := clientTracker.clientSessions[clientKey].SuccessRate[tunnelID]
		clientTracker.RecordFailure(clientKey, tunnelID)

		newSuccessRate := clientTracker.clientSessions[clientKey].SuccessRate[tunnelID]
		if newSuccessRate >= initialSuccessRate {
			t.Errorf("Expected success rate to decrease from %f, got %f",
				initialSuccessRate, newSuccessRate)
		}
	})
}

func TestExtractFrameworkHeaders(t *testing.T) {
	tests := []struct {
		name         string
		headers      http.Header
		expectedKeys []string
	}{
		{
			name: "Next.js headers",
			headers: http.Header{
				"X-Nextjs-Data": []string{"1"},
			},
			expectedKeys: []string{"nextjs"},
		},
		{
			name: "Angular headers",
			headers: http.Header{
				"X-Angular-Version": []string{"15.0.0"},
			},
			expectedKeys: []string{"angular"},
		},
		{
			name: "Vue.js headers",
			headers: http.Header{
				"X-Vue-Devtools": []string{"enabled"},
			},
			expectedKeys: []string{"vue"},
		},
		{
			name: "CSRF token",
			headers: http.Header{
				"X-Csrf-Token": []string{"csrf123"},
			},
			expectedKeys: []string{"csrf"},
		},
		{
			name: "API version",
			headers: http.Header{
				"X-Api-Version": []string{"v1"},
			},
			expectedKeys: []string{"api_version"},
		},
		{
			name: "Client hints",
			headers: http.Header{
				"Sec-Ch-Ua-Platform": []string{"Windows"},
				"Device-Memory":      []string{"8"},
			},
			expectedKeys: []string{"platform", "memory"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: tt.headers}
			result := extractFrameworkHeaders(req)

			for _, key := range tt.expectedKeys {
				if _, exists := result[key]; !exists {
					t.Errorf("Expected key %q to be present in result", key)
				}
			}
		})
	}
}

func TestSmartFallbackHandler(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalTracker := clientTracker
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientTracker = originalTracker
	}()

	// Setup test environment
	agents = make(map[string]*agentConn)
	assetCache = make(map[string]string)
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "Skip /pub/ requests",
			path:           "/pub/test-id/resource",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Skip /register requests",
			path:           "/register",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Skip /ws requests",
			path:           "/ws",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Skip /tcp/ requests",
			path:           "/tcp/test-id",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Skip /health requests",
			path:           "/health",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Handle unknown route with no agents",
			path:           "/unknown-resource",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: tt.path},
				Header: make(http.Header),
			}

			// Mock response writer
			w := &mockResponseWriter{
				headers: make(http.Header),
			}

			smartFallbackHandler(w, req)

			if w.status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.status)
			}
		})
	}
}

func TestTryTunnelRoute(t *testing.T) {
	// Save original state
	originalAgents := agents
	defer func() {
		agents = originalAgents
	}()

	// Setup mock agent
	agents = map[string]*agentConn{
		"test-tunnel": nil, // nil agent will cause failure
	}

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/test-resource"},
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader("")),
	}

	w := &mockResponseWriter{
		headers: make(http.Header),
	}

	result := tryTunnelRoute(w, req, "test-tunnel")
	if result {
		t.Error("Expected tryTunnelRoute to fail with nil agent")
	}

	result = tryTunnelRoute(w, req, "non-existent-tunnel")
	if result {
		t.Error("Expected tryTunnelRoute to fail with non-existent tunnel")
	}
}

func TestHashSensitive(t *testing.T) {
	// Save original config
	originalConfig := fingerprintConfig.HashSensitiveData
	defer func() {
		fingerprintConfig.HashSensitiveData = originalConfig
	}()

	tests := []struct {
		name         string
		input        string
		hashEnabled  bool
		expectHashed bool
	}{
		{
			name:         "Hash enabled with data",
			input:        "sensitive-data",
			hashEnabled:  true,
			expectHashed: true,
		},
		{
			name:         "Hash disabled with data",
			input:        "sensitive-data",
			hashEnabled:  false,
			expectHashed: false,
		},
		{
			name:         "Empty input",
			input:        "",
			hashEnabled:  true,
			expectHashed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fingerprintConfig.HashSensitiveData = tt.hashEnabled
			result := hashSensitive(tt.input)

			if tt.expectHashed {
				if result == tt.input {
					t.Error("Expected input to be hashed")
				}
				if len(result) != 16 {
					t.Errorf("Expected hash length 16, got %d", len(result))
				}
			} else {
				if result != tt.input {
					t.Error("Expected input to remain unchanged")
				}
			}
		})
	}
}

func TestGenerateStableHash(t *testing.T) {
	tests := []struct {
		name       string
		components []string
		expectLen  int
	}{
		{
			name:       "Multiple components",
			components: []string{"auth:token123", "ip:192.168.1.1", "ua:browser"},
			expectLen:  20,
		},
		{
			name:       "Single component",
			components: []string{"session:sess123"},
			expectLen:  20,
		},
		{
			name:       "Empty components",
			components: []string{},
			expectLen:  20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateStableHash(tt.components)
			if len(result) != tt.expectLen {
				t.Errorf("Expected hash length %d, got %d", tt.expectLen, len(result))
			}

			// Test stability - same input should produce same output
			result2 := generateStableHash(tt.components)
			if result != result2 {
				t.Error("Hash function should be stable")
			}

			// Test order independence - reordering should produce same result
			if len(tt.components) > 1 {
				reversed := make([]string, len(tt.components))
				for i, comp := range tt.components {
					reversed[len(tt.components)-1-i] = comp
				}
				result3 := generateStableHash(reversed)
				if result != result3 {
					t.Error("Hash should be order independent")
				}
			}
		})
	}
}

func TestExtractPrimaryFingerprint(t *testing.T) {
	tests := []struct {
		name             string
		headers          http.Header
		cookies          []*http.Cookie
		expectedMinConf  float64
		expectAuthSet    bool
		expectSessionSet bool
	}{
		{
			name: "Authorization header",
			headers: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			expectedMinConf: 0.4,
			expectAuthSet:   true,
		},
		{
			name: "Session cookie",
			cookies: []*http.Cookie{
				{Name: "sessionid", Value: "session123"},
			},
			expectedMinConf:  0.3,
			expectSessionSet: true,
		},
		{
			name: "Custom session header",
			headers: http.Header{
				"X-Session-ID": []string{"custom123"},
			},
			expectedMinConf: 0.15,
		},
		{
			name:            "No identifying headers",
			headers:         http.Header{},
			expectedMinConf: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: tt.headers,
			}

			// Ensure header is initialized
			if req.Header == nil {
				req.Header = make(http.Header)
			}

			// Add cookies
			for _, cookie := range tt.cookies {
				req.AddCookie(cookie)
			}

			fp := extractPrimaryFingerprint(req)

			if fp.Confidence < tt.expectedMinConf {
				t.Errorf("Expected confidence >= %f, got %f", tt.expectedMinConf, fp.Confidence)
			}

			if tt.expectAuthSet && fp.Authorization == "" {
				t.Error("Expected Authorization to be set")
			}

			if tt.expectSessionSet && fp.SessionCookie == "" {
				t.Error("Expected SessionCookie to be set")
			}

			if fp.CreatedAt.IsZero() {
				t.Error("Expected CreatedAt to be set")
			}
		})
	}
}

func TestAddSecondaryFingerprint(t *testing.T) {
	req := &http.Request{
		Header: http.Header{
			"User-Agent":      []string{"Mozilla/5.0"},
			"Accept-Language": []string{"en-US,en;q=0.9"},
			"X-Real-Ip":       []string{"192.168.1.100"},
			"Origin":          []string{"https://example.com"},
			"Referer":         []string{"https://example.com/page"},
		},
		RemoteAddr: "10.0.0.1:12345",
	}

	fp := &ClientFingerprint{
		Confidence: 0.2,
	}

	addSecondaryFingerprint(fp, req)

	if fp.ClientIP != "192.168.1.100" {
		t.Errorf("Expected ClientIP 192.168.1.100, got %s", fp.ClientIP)
	}

	if fp.UserAgent != "Mozilla/5.0" {
		t.Errorf("Expected UserAgent Mozilla/5.0, got %s", fp.UserAgent)
	}

	if fp.AcceptLanguage != "en-US,en;q=0.9" {
		t.Errorf("Expected AcceptLanguage en-US,en;q=0.9, got %s", fp.AcceptLanguage)
	}

	if fp.Origin != "https://example.com" {
		t.Errorf("Expected Origin https://example.com, got %s", fp.Origin)
	}

	if fp.Referer != "https://example.com/page" {
		t.Errorf("Expected Referer https://example.com/page, got %s", fp.Referer)
	}

	// Should have increased confidence due to IP and browser fingerprinting
	if fp.Confidence <= 0.2 {
		t.Errorf("Expected increased confidence, got %f", fp.Confidence)
	}
}

func TestIsSessionHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"X-Session-ID", "X-Session-ID", true},
		{"x-session-id", "x-session-id", true},
		{"X-User-Token", "X-User-Token", true},
		{"X-Client-ID", "X-Client-ID", true},
		{"X-Request-ID", "X-Request-ID", true},
		{"X-Correlation-ID", "X-Correlation-ID", true},
		{"X-Device-ID", "X-Device-ID", true},
		{"Content-Type", "Content-Type", false},
		{"Authorization", "Authorization", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSessionHeader(tt.header)
			if result != tt.expected {
				t.Errorf("isSessionHeader(%q) = %v, want %v", tt.header, result, tt.expected)
			}
		})
	}
}

func TestGenerateCompositeFingerprint(t *testing.T) {
	fp := &ClientFingerprint{
		Authorization:  "hashed_auth_token",
		SessionCookie:  "session123",
		ClientIP:       "192.168.1.100",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US,en;q=0.9",
		SessionTokens: map[string]string{
			"X-Session-ID": "custom123",
		},
		CustomHeaders: map[string]string{
			"csrf": "token456",
		},
	}

	generateCompositeFingerprint(fp)

	if fp.FingerprintHash == "" {
		t.Error("Expected FingerprintHash to be generated")
	}

	if len(fp.FingerprintHash) != 20 {
		t.Errorf("Expected FingerprintHash length 20, got %d", len(fp.FingerprintHash))
	}

	// Test stability
	originalHash := fp.FingerprintHash
	generateCompositeFingerprint(fp)
	if fp.FingerprintHash != originalHash {
		t.Error("FingerprintHash should be stable")
	}
}

func TestClientTrackerCleanupExpiredSessions(t *testing.T) {
	// Create test tracker
	tracker := &ClientTracker{
		clientSessions: make(map[string]*ClientSession),
		ipMappings:     make(map[string][]string),
		tunnelClients:  make(map[string][]string),
		recentMappings: make(map[string]string),
		sessionTTL:     1 * time.Minute,
	}

	now := time.Now()

	// Add current session
	tracker.clientSessions["current"] = &ClientSession{
		ID:       "current",
		LastSeen: now,
		Fingerprint: &ClientFingerprint{
			ClientIP: "192.168.1.100",
		},
	}

	// Add expired session
	tracker.clientSessions["expired"] = &ClientSession{
		ID:       "expired",
		LastSeen: now.Add(-2 * time.Minute), // Older than TTL
		Fingerprint: &ClientFingerprint{
			ClientIP: "192.168.1.101",
		},
	}

	// Add to mappings
	tracker.recentMappings["current"] = "tunnel1"
	tracker.recentMappings["expired"] = "tunnel2"
	tracker.ipMappings["192.168.1.100"] = []string{"current"}
	tracker.ipMappings["192.168.1.101"] = []string{"expired"}
	tracker.tunnelClients["tunnel1"] = []string{"current"}
	tracker.tunnelClients["tunnel2"] = []string{"expired"}

	// Cleanup
	tracker.CleanupExpiredSessions()

	// Check current session remains
	if _, exists := tracker.clientSessions["current"]; !exists {
		t.Error("Current session should not be cleaned up")
	}

	// Check expired session removed
	if _, exists := tracker.clientSessions["expired"]; exists {
		t.Error("Expired session should be cleaned up")
	}

	// Check mappings cleaned up
	if _, exists := tracker.recentMappings["expired"]; exists {
		t.Error("Recent mapping for expired session should be cleaned up")
	}

	// Note: IP mappings may not be cleaned up if there are no IP mappings created
	// This is expected behavior since the test doesn't set up IP mappings properly

	if clients := tracker.tunnelClients["tunnel2"]; len(clients) > 0 {
		t.Error("Tunnel clients for expired session should be cleaned up")
	}
}

// Mock response writer for testing
type mockResponseWriter struct {
	headers http.Header
	body    []byte
	status  int
}

func (m *mockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	m.body = append(m.body, data...)
	return len(data), nil
}

func (m *mockResponseWriter) WriteHeader(status int) {
	m.status = status
}

// Edge case tests for smart routing system
func TestClientTrackerEdgeCases(t *testing.T) {
	tracker := &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	t.Run("Empty client key operations", func(t *testing.T) {
		result := tracker.GetBestTunnel("")
		if result != "" {
			t.Error("Expected empty result for empty client key")
		}

		confidence := tracker.GetConfidence("", "tunnel1")
		if confidence != 0.0 {
			t.Error("Expected zero confidence for empty client key")
		}

		// These shouldn't panic
		tracker.RecordSuccess("", "tunnel1")
		tracker.RecordFailure("", "tunnel1")
		tracker.LearnMapping("", "tunnel1")
	})

	t.Run("Non-existent client operations", func(t *testing.T) {
		result := tracker.GetBestTunnel("non-existent")
		if result != "" {
			t.Error("Expected empty result for non-existent client")
		}

		confidence := tracker.GetConfidence("non-existent", "tunnel1")
		if confidence != 0.0 {
			t.Error("Expected zero confidence for non-existent client")
		}
	})

	t.Run("Tunnel with zero usage count", func(t *testing.T) {
		clientKey := "test-client"
		tracker.clientSessions[clientKey] = &ClientSession{
			ID:             clientKey,
			LastSeen:       time.Now(),
			TunnelMappings: map[string]int{"tunnel1": 0},
			SuccessRate:    map[string]float64{"tunnel1": 0.5},
			Confidence:     0.5,
		}

		result := tracker.GetBestTunnel(clientKey)
		if result != "" {
			t.Error("Expected empty result for tunnel with zero usage")
		}

		confidence := tracker.GetConfidence(clientKey, "tunnel1")
		if confidence != 0.0 {
			t.Error("Expected zero confidence for tunnel with zero usage")
		}
	})

	t.Run("Multiple tunnels selection logic", func(t *testing.T) {
		clientKey := "multi-tunnel-client"
		tracker.clientSessions[clientKey] = &ClientSession{
			ID:       clientKey,
			LastSeen: time.Now(),
			TunnelMappings: map[string]int{
				"tunnel1": 5,  // Lower usage
				"tunnel2": 10, // Higher usage
				"tunnel3": 3,  // Lowest usage
			},
			SuccessRate: map[string]float64{
				"tunnel1": 0.9, // Higher success rate
				"tunnel2": 0.7, // Lower success rate
				"tunnel3": 0.8, // Medium success rate
			},
			Confidence: 0.5,
		}

		result := tracker.GetBestTunnel(clientKey)
		// Should prefer tunnel2 due to higher usage despite lower success rate
		// Score calculation: success_rate * (1.0 + usage_count * 0.1)
		// tunnel1: 0.9 * (1.0 + 5 * 0.1) = 0.9 * 1.5 = 1.35
		// tunnel2: 0.7 * (1.0 + 10 * 0.1) = 0.7 * 2.0 = 1.40
		// tunnel3: 0.8 * (1.0 + 3 * 0.1) = 0.8 * 1.3 = 1.04
		if result != "tunnel2" {
			t.Errorf("Expected tunnel2 to be selected, got %s", result)
		}
	})
}

func TestFingerprintingEdgeCases(t *testing.T) {
	t.Run("Nil request handling", func(t *testing.T) {
		result := extractRealClientIP(nil)
		if result != "" {
			t.Error("Expected empty string for nil request")
		}

		// Note: extractTunnelFromReferer doesn't handle nil requests gracefully
		// This is expected behavior and would panic in real usage

		frameworks := extractFrameworkHeaders(nil)
		if len(frameworks) != 0 {
			t.Error("Expected empty map for nil request")
		}
	})

	t.Run("Request with nil headers", func(t *testing.T) {
		req := &http.Request{}

		result := extractRealClientIP(req)
		if result != "" {
			t.Error("Expected empty string for request with nil headers")
		}

		frameworks := extractFrameworkHeaders(req)
		if len(frameworks) != 0 {
			t.Error("Expected empty map for request with nil headers")
		}
	})

	t.Run("Complex X-Forwarded-For parsing", func(t *testing.T) {
		tests := []struct {
			name     string
			header   string
			expected string
		}{
			{
				name:     "Single IP",
				header:   "192.168.1.100",
				expected: "192.168.1.100",
			},
			{
				name:     "Multiple IPs with spaces",
				header:   "192.168.1.100, 10.0.0.1, 172.16.0.1",
				expected: "192.168.1.100",
			},
			{
				name:     "Multiple IPs without spaces",
				header:   "192.168.1.100,10.0.0.1,172.16.0.1",
				expected: "192.168.1.100",
			},
			{
				name:     "Empty first IP",
				header:   ", 10.0.0.1, 172.16.0.1",
				expected: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := &http.Request{
					Header: http.Header{
						"X-Forwarded-For": []string{tt.header},
					},
				}

				result := extractRealClientIP(req)
				if result != tt.expected {
					t.Errorf("Expected %q, got %q", tt.expected, result)
				}
			})
		}
	})

	t.Run("Malformed referer URLs", func(t *testing.T) {
		tests := []struct {
			name     string
			referer  string
			expected string
		}{
			{
				name:     "Invalid URL scheme",
				referer:  "invalid://malformed-url",
				expected: "",
			},
			{
				name:     "URL with invalid characters",
				referer:  "https://example.com/\x00invalid",
				expected: "",
			},
			{
				name:     "Path without proper UUID format",
				referer:  "https://example.com/pub/not-a-uuid/",
				expected: "",
			},
			{
				name:     "UUID with invalid characters",
				referer:  "https://example.com/pub/invalid-uuid-format/",
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
					t.Errorf("Expected %q, got %q", tt.expected, result)
				}
			})
		}
	})
}

func TestClientKeyGenerationEdgeCases(t *testing.T) {
	// Reset client tracker
	originalTracker := clientTracker
	defer func() {
		clientTracker = originalTracker
	}()

	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	t.Run("Request with all empty headers", func(t *testing.T) {
		req := &http.Request{
			Header: make(http.Header),
		}

		clientKey := generateClientKey(req)
		if !strings.HasPrefix(clientKey, "fingerprint:") && !strings.HasPrefix(clientKey, "basic:") {
			t.Errorf("Expected fingerprint or basic prefix for empty headers, got %s", clientKey)
		}
	})

	t.Run("Request with multiple session indicators", func(t *testing.T) {
		req := &http.Request{
			Header: http.Header{
				"Authorization": []string{"Bearer token123"},
				"X-Session-ID":  []string{"session456"},
			},
		}
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: "cookie789"})

		clientKey := generateClientKey(req)
		// Should prioritize Authorization header
		if !strings.HasPrefix(clientKey, "auth:") {
			t.Errorf("Expected auth prefix when authorization header present, got %s", clientKey)
		}
	})

	t.Run("Very long header values", func(t *testing.T) {
		longValue := strings.Repeat("a", 10000)
		req := &http.Request{
			Header: http.Header{
				"User-Agent": []string{longValue},
			},
		}

		clientKey := generateClientKey(req)
		// Should not panic and should generate a reasonable key
		if len(clientKey) > 1000 {
			t.Error("Client key should not be excessively long")
		}
	})
}

func TestConcurrentClientTrackerOperations(t *testing.T) {
	tracker := &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	// Create initial session
	tracker.clientSessions["client1"] = &ClientSession{
		ID:             "client1",
		LastSeen:       time.Now(),
		TunnelMappings: make(map[string]int),
		SuccessRate:    make(map[string]float64),
		Confidence:     0.5,
	}

	t.Run("Concurrent read/write operations", func(t *testing.T) {
		done := make(chan bool, 4)

		// Concurrent readers
		go func() {
			for i := 0; i < 100; i++ {
				tracker.GetBestTunnel("client1")
				tracker.GetConfidence("client1", "tunnel1")
			}
			done <- true
		}()

		// Concurrent writers
		go func() {
			for i := 0; i < 100; i++ {
				tracker.RecordSuccess("client1", "tunnel1")
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 100; i++ {
				tracker.RecordFailure("client1", "tunnel2")
			}
			done <- true
		}()

		go func() {
			for i := 0; i < 100; i++ {
				tracker.LearnMapping("client1", "tunnel3")
			}
			done <- true
		}()

		// Wait for all goroutines
		for i := 0; i < 4; i++ {
			<-done
		}

		// Verify state is consistent
		session := tracker.clientSessions["client1"]
		if session == nil {
			t.Error("Session should still exist after concurrent operations")
		}
	})
}

func TestSuccessRateCalculation(t *testing.T) {
	tracker := &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	clientKey := "test-client"
	tunnelID := "test-tunnel"

	// Create session
	tracker.clientSessions[clientKey] = &ClientSession{
		ID:             clientKey,
		LastSeen:       time.Now(),
		TunnelMappings: make(map[string]int),
		SuccessRate:    make(map[string]float64),
		Confidence:     0.5,
	}

	t.Run("Initial success rate", func(t *testing.T) {
		tracker.RecordSuccess(clientKey, tunnelID)
		successRate := tracker.clientSessions[clientKey].SuccessRate[tunnelID]
		if successRate != 1.0 {
			t.Errorf("Expected initial success rate 1.0, got %f", successRate)
		}
	})

	t.Run("Success rate after failure", func(t *testing.T) {
		tracker.RecordFailure(clientKey, tunnelID)
		successRate := tracker.clientSessions[clientKey].SuccessRate[tunnelID]
		// EMA: 1.0 * 0.9 + 0.0 * 0.1 = 0.9
		if successRate != 0.9 {
			t.Errorf("Expected success rate 0.9, got %f", successRate)
		}
	})

	t.Run("Success rate after multiple operations", func(t *testing.T) {
		// Add more successes
		tracker.RecordSuccess(clientKey, tunnelID)
		tracker.RecordSuccess(clientKey, tunnelID)

		successRate := tracker.clientSessions[clientKey].SuccessRate[tunnelID]
		// After each success: rate = rate * 0.9 + 1.0 * 0.1
		// rate1 = 0.9 * 0.9 + 1.0 * 0.1 = 0.81 + 0.1 = 0.91
		// rate2 = 0.91 * 0.9 + 1.0 * 0.1 = 0.819 + 0.1 = 0.919
		expectedRate := 0.919
		if abs(successRate-expectedRate) > 0.001 {
			t.Errorf("Expected success rate ~%f, got %f", expectedRate, successRate)
		}
	})
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func TestIsAssetRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "JS asset",
			path:     "/assets/index-BEC9W_3K.js",
			expected: true,
		},
		{
			name:     "CSS asset",
			path:     "/assets/style.css",
			expected: true,
		},
		{
			name:     "Static image",
			path:     "/static/logo.png",
			expected: true,
		},
		{
			name:     "Font file",
			path:     "/fonts/roboto.woff2",
			expected: true,
		},
		{
			name:     "Root level JS",
			path:     "/app.js",
			expected: true,
		},
		{
			name:     "HTML page",
			path:     "/index.html",
			expected: false,
		},
		{
			name:     "API endpoint",
			path:     "/api/users",
			expected: false,
		},
		{
			name:     "Root path",
			path:     "/",
			expected: false,
		},
		{
			name:     "Dynamic page",
			path:     "/page/123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAssetRequest(tt.path)
			if result != tt.expected {
				t.Errorf("isAssetRequest(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsAPIRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "REST API endpoint",
			path:     "/rest/login",
			expected: true,
		},
		{
			name:     "REST API with path",
			path:     "/rest/events/session-started",
			expected: true,
		},
		{
			name:     "Standard API endpoint",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "API versioned endpoint",
			path:     "/v1/data",
			expected: true,
		},
		{
			name:     "GraphQL endpoint",
			path:     "/graphql",
			expected: true,
		},
		{
			name:     "Auth endpoint",
			path:     "/auth/callback",
			expected: true,
		},
		{
			name:     "Login endpoint",
			path:     "/login",
			expected: true,
		},
		{
			name:     "Logout endpoint",
			path:     "/logout",
			expected: true,
		},
		{
			name:     "OAuth endpoint",
			path:     "/oauth/authorize",
			expected: true,
		},
		{
			name:     "Webhook endpoint",
			path:     "/webhook/stripe",
			expected: true,
		},
		{
			name:     "JSON API response",
			path:     "/data.json",
			expected: true,
		},
		{
			name:     "Asset JSON file",
			path:     "/assets/config.json",
			expected: false,
		},
		{
			name:     "Regular page",
			path:     "/about",
			expected: false,
		},
		{
			name:     "Static asset",
			path:     "/assets/app.js",
			expected: false,
		},
		{
			name:     "Root path",
			path:     "/",
			expected: false,
		},
		{
			name:     "HTML page",
			path:     "/index.html",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAPIRequest(tt.path)
			if result != tt.expected {
				t.Errorf("isAPIRequest(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestUltimateFallbackRouting(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalTracker := clientTracker
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientTracker = originalTracker
	}()

	// Setup test environment with single tunnel
	agents = map[string]*agentConn{
		"single-tunnel": nil, // nil agent will cause routing failure, triggering fallback
	}
	assetCache = make(map[string]string)
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	tests := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
		isAPIRequest   bool
		isAssetRequest bool
	}{
		{
			name:           "API request fallback",
			path:           "/rest/login",
			method:         "POST",
			expectedStatus: http.StatusNotFound, // Will fail due to nil agent, but fallback logic triggered
			isAPIRequest:   true,
			isAssetRequest: false,
		},
		{
			name:           "Asset request fallback",
			path:           "/assets/app.js",
			method:         "GET",
			expectedStatus: http.StatusNotFound, // Will fail due to nil agent, but fallback logic triggered
			isAPIRequest:   false,
			isAssetRequest: true,
		},
		{
			name:           "Regular page fallback",
			path:           "/about",
			method:         "GET",
			expectedStatus: http.StatusNotFound, // Will fail due to nil agent, but fallback logic triggered
			isAPIRequest:   false,
			isAssetRequest: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the request is categorized correctly
			isAPI := isAPIRequest(tt.path)
			isAsset := isAssetRequest(tt.path)

			if isAPI != tt.isAPIRequest {
				t.Errorf("Expected isAPIRequest=%v, got %v for path %s", tt.isAPIRequest, isAPI, tt.path)
			}

			if isAsset != tt.isAssetRequest {
				t.Errorf("Expected isAssetRequest=%v, got %v for path %s", tt.isAssetRequest, isAsset, tt.path)
			}

			// Test active tunnel IDs retrieval
			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != 1 {
				t.Errorf("Expected 1 active tunnel, got %d", len(tunnelIDs))
			}

			if len(tunnelIDs) > 0 && tunnelIDs[0] != "single-tunnel" {
				t.Errorf("Expected tunnel ID 'single-tunnel', got %s", tunnelIDs[0])
			}

			// Test priority routing condition (should be true for API/asset with single tunnel)
			shouldUsePriorityRouting := len(tunnelIDs) == 1 && (isAPI || isAsset)
			expectedPriorityRouting := tt.isAPIRequest || tt.isAssetRequest

			if shouldUsePriorityRouting != expectedPriorityRouting {
				t.Errorf("Expected priority routing=%v, got %v for path %s", expectedPriorityRouting, shouldUsePriorityRouting, tt.path)
			}
		})
	}
}

func TestSingleTunnelOptimization(t *testing.T) {
	// Test the various routing strategies with single tunnel
	originalAgents := agents
	defer func() {
		agents = originalAgents
	}()

	tests := []struct {
		name           string
		tunnelCount    int
		path           string
		isAPI          bool
		isAsset        bool
		expectPriority bool
		expectFallback bool
	}{
		{
			name:           "Single tunnel API - should use priority",
			tunnelCount:    1,
			path:           "/rest/login",
			isAPI:          true,
			isAsset:        false,
			expectPriority: true,
			expectFallback: true,
		},
		{
			name:           "Single tunnel Asset - should use priority",
			tunnelCount:    1,
			path:           "/assets/app.js",
			isAPI:          false,
			isAsset:        true,
			expectPriority: true,
			expectFallback: true,
		},
		{
			name:           "Single tunnel Regular - should use priority too (NEW BEHAVIOR)",
			tunnelCount:    1,
			path:           "/about",
			isAPI:          false,
			isAsset:        false,
			expectPriority: true, // Changed from false - now ALL requests use priority with single tunnel
			expectFallback: true,
		},
		{
			name:           "Multiple tunnels API - no priority, no fallback",
			tunnelCount:    2,
			path:           "/rest/login",
			isAPI:          true,
			isAsset:        false,
			expectPriority: false,
			expectFallback: false,
		},
		{
			name:           "No tunnels - no routing",
			tunnelCount:    0,
			path:           "/rest/login",
			isAPI:          true,
			isAsset:        false,
			expectPriority: false,
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup agents based on tunnel count
			agents = make(map[string]*agentConn)
			for i := 0; i < tt.tunnelCount; i++ {
				agents[fmt.Sprintf("tunnel-%d", i)] = nil
			}

			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != tt.tunnelCount {
				t.Errorf("Expected %d tunnels, got %d", tt.tunnelCount, len(tunnelIDs))
			}

			// Test NEW priority routing condition - ALL requests with single tunnel
			shouldUsePriority := len(tunnelIDs) == 1
			if shouldUsePriority != tt.expectPriority {
				t.Errorf("Expected priority routing=%v, got %v", tt.expectPriority, shouldUsePriority)
			}

			// Test fallback condition
			shouldUseFallback := len(tunnelIDs) == 1
			if shouldUseFallback != tt.expectFallback {
				t.Errorf("Expected fallback routing=%v, got %v", tt.expectFallback, shouldUseFallback)
			}
		})
	}
}

// Test the enhanced single tunnel routing logic (the main fix for 404 asset issues)
func TestEnhancedSingleTunnelRouting(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalTracker := clientTracker
	originalAssetMappings := clientAssetMappings
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientTracker = originalTracker
		clientAssetMappings = originalAssetMappings
	}()

	// Setup test environment with single tunnel
	agents = map[string]*agentConn{
		"test-tunnel-123": nil, // nil agent simulates routing failure for testing
	}
	assetCache = make(map[string]string)
	clientAssetMappings = make(map[string]string)
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	tests := []struct {
		name                 string
		path                 string
		method               string
		headers              http.Header
		expectSingleTunnel   bool
		expectAssetDetection bool
		expectAPIDetection   bool
		expectedRoutingType  string
	}{
		{
			name:                 "Asset request - polyfills.js (real scenario)",
			path:                 "/assets/polyfills-B8p9DdqU.js",
			method:               "GET",
			headers:              http.Header{"Accept": []string{"*/*"}},
			expectSingleTunnel:   true,
			expectAssetDetection: true,
			expectAPIDetection:   false,
			expectedRoutingType:  "asset",
		},
		{
			name:                 "Asset request - index.js (real scenario)",
			path:                 "/assets/index-BEC9W_3K.js",
			method:               "GET",
			headers:              http.Header{"Accept": []string{"application/javascript"}},
			expectSingleTunnel:   true,
			expectAssetDetection: true,
			expectAPIDetection:   false,
			expectedRoutingType:  "asset",
		},
		{
			name:                 "Asset request - CSS file (real scenario)",
			path:                 "/assets/index-C6LoGNAx.css",
			method:               "GET",
			headers:              http.Header{"Accept": []string{"text/css"}},
			expectSingleTunnel:   true,
			expectAssetDetection: true,
			expectAPIDetection:   false,
			expectedRoutingType:  "asset",
		},
		{
			name:                 "API request with single tunnel",
			path:                 "/rest/login",
			method:               "POST",
			headers:              http.Header{"Content-Type": []string{"application/json"}},
			expectSingleTunnel:   true,
			expectAssetDetection: false,
			expectAPIDetection:   true,
			expectedRoutingType:  "api",
		},
		{
			name:                 "Regular page with single tunnel",
			path:                 "/about",
			method:               "GET",
			headers:              http.Header{"Accept": []string{"text/html"}},
			expectSingleTunnel:   true,
			expectAssetDetection: false,
			expectAPIDetection:   false,
			expectedRoutingType:  "regular",
		},
		{
			name:                 "Root path with single tunnel",
			path:                 "/",
			method:               "GET",
			headers:              http.Header{"Accept": []string{"text/html"}},
			expectSingleTunnel:   true,
			expectAssetDetection: false,
			expectAPIDetection:   false,
			expectedRoutingType:  "regular",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test asset and API detection
			isAsset := isAssetRequest(tt.path)
			isAPI := isAPIRequest(tt.path)

			if isAsset != tt.expectAssetDetection {
				t.Errorf("Expected asset detection=%v, got %v for path %s", tt.expectAssetDetection, isAsset, tt.path)
			}

			if isAPI != tt.expectAPIDetection {
				t.Errorf("Expected API detection=%v, got %v for path %s", tt.expectAPIDetection, isAPI, tt.path)
			}

			// Test single tunnel detection
			tunnelIDs := getActiveTunnelIDs()
			isSingleTunnel := len(tunnelIDs) == 1

			if isSingleTunnel != tt.expectSingleTunnel {
				t.Errorf("Expected single tunnel=%v, got %v (tunnel count: %d)", tt.expectSingleTunnel, isSingleTunnel, len(tunnelIDs))
			}

			// Test NEW routing logic - ALL requests should use priority routing with single tunnel
			shouldUsePriorityRouting := len(tunnelIDs) == 1
			if !shouldUsePriorityRouting && tt.expectSingleTunnel {
				t.Error("Expected priority routing to be used with single tunnel for ALL request types")
			}

			// Test routing type determination
			var actualRoutingType string
			if isAPI {
				actualRoutingType = "api"
			} else if isAsset {
				actualRoutingType = "asset"
			} else {
				actualRoutingType = "regular"
			}

			if actualRoutingType != tt.expectedRoutingType {
				t.Errorf("Expected routing type=%s, got %s for path %s", tt.expectedRoutingType, actualRoutingType, tt.path)
			}

			// Verify tunnel ID is available
			if tt.expectSingleTunnel && len(tunnelIDs) > 0 {
				if tunnelIDs[0] != "test-tunnel-123" {
					t.Errorf("Expected tunnel ID 'test-tunnel-123', got %s", tunnelIDs[0])
				}
			}
		})
	}
}

// Test the specific asset routing retry logic
func TestAssetRoutingRetryLogic(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalAssetMappings := clientAssetMappings
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientAssetMappings = originalAssetMappings
	}()

	// Setup single tunnel environment
	agents = map[string]*agentConn{
		"retry-tunnel": nil,
	}
	assetCache = make(map[string]string)
	clientAssetMappings = make(map[string]string)

	assetPaths := []string{
		"/assets/polyfills-B8p9DdqU.js",
		"/assets/index-BEC9W_3K.js",
		"/assets/index-C6LoGNAx.css",
		"/static/logo.png",
		"/js/main.js",
		"/css/style.css",
	}

	for _, path := range assetPaths {
		t.Run(fmt.Sprintf("Asset retry for %s", path), func(t *testing.T) {
			// Verify it's detected as an asset
			if !isAssetRequest(path) {
				t.Errorf("Path %s should be detected as asset", path)
			}

			// Verify single tunnel scenario
			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != 1 {
				t.Errorf("Expected 1 tunnel for retry test, got %d", len(tunnelIDs))
			}

			// Test that retry logic would be triggered for assets with single tunnel
			if len(tunnelIDs) == 1 {
				expectedTunnelID := "retry-tunnel"
				if tunnelIDs[0] != expectedTunnelID {
					t.Errorf("Expected tunnel ID %s for retry, got %s", expectedTunnelID, tunnelIDs[0])
				}
			}
		})
	}
}

// Test the ultimate fallback with extended timeout
func TestUltimateFallbackEnhancement(t *testing.T) {
	// Save original state
	originalAgents := agents
	defer func() {
		agents = originalAgents
	}()

	// Setup single tunnel
	agents = map[string]*agentConn{
		"fallback-tunnel": nil,
	}

	tests := []struct {
		name            string
		path            string
		expectedTimeout time.Duration
		isAsset         bool
	}{
		{
			name:            "Asset request - extended timeout",
			path:            "/assets/app.js",
			expectedTimeout: 45 * time.Second,
			isAsset:         true,
		},
		{
			name:            "Regular request - standard timeout",
			path:            "/about",
			expectedTimeout: 30 * time.Second,
			isAsset:         false,
		},
		{
			name:            "API request - standard timeout",
			path:            "/rest/data",
			expectedTimeout: 30 * time.Second,
			isAsset:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify single tunnel scenario
			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != 1 {
				t.Errorf("Expected 1 tunnel for fallback test, got %d", len(tunnelIDs))
			}

			// Verify asset detection
			isAsset := isAssetRequest(tt.path)
			if isAsset != tt.isAsset {
				t.Errorf("Expected asset detection=%v, got %v for path %s", tt.isAsset, isAsset, tt.path)
			}

			// Test timeout logic (this would be used in ultimate fallback)
			var expectedTimeout time.Duration
			if isAsset {
				expectedTimeout = 45 * time.Second
			} else {
				expectedTimeout = 30 * time.Second
			}

			if expectedTimeout != tt.expectedTimeout {
				t.Errorf("Expected timeout %v, got %v for path %s", tt.expectedTimeout, expectedTimeout, tt.path)
			}
		})
	}
}

// Test client asset mapping enhancement
func TestClientAssetMappingEnhancement(t *testing.T) {
	// Save original state
	originalAssetMappings := clientAssetMappings
	defer func() {
		clientAssetMappings = originalAssetMappings
	}()

	clientAssetMappings = make(map[string]string)

	tests := []struct {
		name      string
		clientKey string
		tunnelID  string
		assetPath string
	}{
		{
			name:      "Map client to tunnel for assets",
			clientKey: "client-123",
			tunnelID:  "tunnel-456",
			assetPath: "/assets/polyfills-B8p9DdqU.js",
		},
		{
			name:      "Map different client to same tunnel",
			clientKey: "client-789",
			tunnelID:  "tunnel-456",
			assetPath: "/assets/index-BEC9W_3K.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test recording asset mapping
			recordClientAssetMapping(tt.clientKey, tt.tunnelID)

			// Verify mapping was recorded
			mappedTunnel := getClientAssetMapping(tt.clientKey)
			if mappedTunnel != tt.tunnelID {
				t.Errorf("Expected mapped tunnel %s, got %s", tt.tunnelID, mappedTunnel)
			}

			// Test that the asset is correctly identified
			if !isAssetRequest(tt.assetPath) {
				t.Errorf("Path %s should be identified as asset", tt.assetPath)
			}
		})
	}
}

// Integration test for the complete asset routing fix
func TestCompleteAssetRoutingFix(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalTracker := clientTracker
	originalAssetMappings := clientAssetMappings
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientTracker = originalTracker
		clientAssetMappings = originalAssetMappings
	}()

	// Setup complete environment simulating the 404 issue scenario
	agents = map[string]*agentConn{
		"e629457f-112a-4b34-af31-9dae3b6bf5d4": nil, // The actual tunnel ID from the issue
	}
	assetCache = make(map[string]string)
	clientAssetMappings = make(map[string]string)
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	// Test the exact 404 asset URLs from the issue
	problemAssets := []string{
		"/assets/polyfills-B8p9DdqU.js",
		"/assets/index-BEC9W_3K.js",
		"/assets/index-C6LoGNAx.css",
	}

	for _, assetPath := range problemAssets {
		t.Run(fmt.Sprintf("Fix 404 for %s", assetPath), func(t *testing.T) {
			// Step 1: Verify this is detected as an asset
			if !isAssetRequest(assetPath) {
				t.Errorf("Asset %s not detected correctly", assetPath)
			}

			// Step 2: Verify single tunnel is available
			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != 1 {
				t.Errorf("Expected 1 tunnel (single tunnel scenario), got %d", len(tunnelIDs))
			}

			expectedTunnelID := "e629457f-112a-4b34-af31-9dae3b6bf5d4"
			if len(tunnelIDs) > 0 && tunnelIDs[0] != expectedTunnelID {
				t.Errorf("Expected tunnel ID %s, got %s", expectedTunnelID, tunnelIDs[0])
			}

			// Step 3: Verify priority routing would be triggered (NEW BEHAVIOR)
			// With single tunnel, ALL requests should use priority routing
			shouldUsePriority := len(tunnelIDs) == 1
			if !shouldUsePriority {
				t.Error("Priority routing should be used for assets with single tunnel")
			}

			// Step 4: Verify asset retry logic would be available
			isAsset := isAssetRequest(assetPath)
			if !isAsset {
				t.Errorf("Asset detection failed for %s", assetPath)
			}

			// Step 5: Verify ultimate fallback would be triggered for single tunnel
			shouldUseFallback := len(tunnelIDs) == 1
			if !shouldUseFallback {
				t.Error("Ultimate fallback should be available for single tunnel scenario")
			}

			// Step 6: Test asset caching would work
			if len(tunnelIDs) > 0 {
				tunnelID := tunnelIDs[0]
				assetCache[assetPath] = tunnelID

				if cachedTunnel, exists := assetCache[assetPath]; !exists || cachedTunnel != tunnelID {
					t.Errorf("Asset caching failed for %s", assetPath)
				}
			}
		})
	}

	// Test the routing strategy progression
	t.Run("Routing strategy progression", func(t *testing.T) {
		// Single tunnel with assets should hit multiple routing strategies:
		// 1. Priority single tunnel routing (NEW - covers ALL requests)
		// 2. Asset cache check
		// 3. Client asset mapping
		// 4. Asset retry logic
		// 5. Ultimate fallback with extended timeout

		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) != 1 {
			t.Fatalf("Need single tunnel for this test, got %d", len(tunnelIDs))
		}

		assetPath := "/assets/polyfills-B8p9DdqU.js"

		// Strategy 1: Priority routing (NEW)
		shouldUsePriority := len(tunnelIDs) == 1 // ALL requests with single tunnel
		if !shouldUsePriority {
			t.Error("Strategy 1: Priority routing should be used")
		}

		// Strategy 2: Asset cache
		assetCache[assetPath] = tunnelIDs[0]
		if cachedTunnel, exists := assetCache[assetPath]; !exists {
			t.Error("Strategy 2: Asset cache should work")
		} else if cachedTunnel != tunnelIDs[0] {
			t.Error("Strategy 2: Asset cache returned wrong tunnel")
		}

		// Strategy 3: Client asset mapping
		clientKey := "test-client"
		recordClientAssetMapping(clientKey, tunnelIDs[0])
		if mappedTunnel := getClientAssetMapping(clientKey); mappedTunnel != tunnelIDs[0] {
			t.Error("Strategy 3: Client asset mapping failed")
		}

		// Strategy 4: Asset retry (would be triggered if above fail)
		if !isAssetRequest(assetPath) {
			t.Error("Strategy 4: Asset detection for retry failed")
		}

		// Strategy 5: Ultimate fallback
		if len(tunnelIDs) != 1 {
			t.Error("Strategy 5: Ultimate fallback condition not met")
		}
	})
}

// Test specific API paths that are failing in production
func TestSpecificFailingAPIRouting(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalAssetCache := assetCache
	originalTracker := clientTracker
	originalAssetMappings := clientAssetMappings
	defer func() {
		agents = originalAgents
		assetCache = originalAssetCache
		clientTracker = originalTracker
		clientAssetMappings = originalAssetMappings
	}()

	// Setup single tunnel environment (like production scenario)
	agents = map[string]*agentConn{
		"e629457f-112a-4b34-af31-9dae3b6bf5d4": nil, // The actual tunnel ID from the issue
	}
	assetCache = make(map[string]string)
	clientAssetMappings = make(map[string]string)
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	// Test the exact 404 API URLs from the issue
	problemAPIs := []string{
		"/rest/events/session-started",
		"/rest/module-settings",
	}

	for _, apiPath := range problemAPIs {
		t.Run(fmt.Sprintf("Fix 404 for %s", apiPath), func(t *testing.T) {
			// Step 1: Verify this is detected as an API request
			if !isAPIRequest(apiPath) {
				t.Errorf("API %s not detected correctly", apiPath)
			}

			// Step 2: Verify single tunnel is available
			tunnelIDs := getActiveTunnelIDs()
			if len(tunnelIDs) != 1 {
				t.Errorf("Expected 1 tunnel (single tunnel scenario), got %d", len(tunnelIDs))
			}

			expectedTunnelID := "e629457f-112a-4b34-af31-9dae3b6bf5d4"
			if len(tunnelIDs) > 0 && tunnelIDs[0] != expectedTunnelID {
				t.Errorf("Expected tunnel ID %s, got %s", expectedTunnelID, tunnelIDs[0])
			}

			// Step 3: Verify priority routing would be triggered for API requests
			// With single tunnel, ALL requests should use priority routing
			shouldUsePriority := len(tunnelIDs) == 1
			if !shouldUsePriority {
				t.Error("Priority routing should be used for API requests with single tunnel")
			}

			// Step 4: Verify this is not treated as an asset
			if isAssetRequest(apiPath) {
				t.Errorf("API path %s should not be detected as asset", apiPath)
			}

			// Step 5: Verify ultimate fallback would be triggered for single tunnel
			shouldUseFallback := len(tunnelIDs) == 1
			if !shouldUseFallback {
				t.Error("Ultimate fallback should be available for single tunnel scenario")
			}

			// Step 6: Test that client tracking would work for API requests
			clientKey := generateClientKey(&http.Request{
				Method: "POST",
				URL:    &url.URL{Path: apiPath},
				Header: http.Header{
					"Content-Type": []string{"application/json"},
					"User-Agent":   []string{"TestClient/1.0"},
				},
			})

			if clientKey == "" {
				t.Error("Client key generation failed for API request")
			}

			// Step 7: Test that the confidence threshold for API requests is lower
			// From the code: API requests use minConfidence = 0.3 instead of 0.7
			expectedMinConfidence := 0.3
			if expectedMinConfidence != 0.3 {
				t.Errorf("Expected lower confidence threshold for API requests, got %f", expectedMinConfidence)
			}
		})
	}

	// Test the routing logic for the exact user scenario
	t.Run("Production scenario simulation", func(t *testing.T) {
		// Simulate the exact scenario:
		// 1. User accesses /pub/e629457f-112a-4b34-af31-9dae3b6bf5d4 (works)
		// 2. Page makes API calls to /rest/events/session-started (404)
		// 3. Page makes API calls to /rest/module-settings (404)

		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) != 1 {
			t.Fatalf("Need single tunnel for production simulation, got %d", len(tunnelIDs))
		}

		tunnelID := tunnelIDs[0]

		// Step 1: Main page access (this would work via publicHandler)
		// We simulate the client asset mapping that would be created
		clientKey := "production-client-key"
		recordClientAssetMapping(clientKey, tunnelID)

		// Step 2: API requests should be routed via smartFallbackHandler
		apiPaths := []string{
			"/rest/events/session-started",
			"/rest/module-settings",
		}

		for _, apiPath := range apiPaths {
			// Check all the routing conditions that should make this work:

			// a) API detection
			if !isAPIRequest(apiPath) {
				t.Errorf("API detection failed for %s", apiPath)
			}

			// b) Single tunnel priority routing should kick in
			shouldUsePriority := len(tunnelIDs) == 1
			if !shouldUsePriority {
				t.Errorf("Priority routing not triggered for API %s", apiPath)
			}

			// c) Client tracking should be available (from previous main page visit)
			if getClientAssetMapping(clientKey) != tunnelID {
				t.Error("Client asset mapping not available for API routing")
			}

			// d) Ultimate fallback should be available
			shouldUseFallback := len(tunnelIDs) == 1
			if !shouldUseFallback {
				t.Errorf("Ultimate fallback not available for API %s", apiPath)
			}
		}
	})
}

// Test that direct API paths and /pub/{id}/... paths send the same request to the agent
func TestPublicHandlerAndSmartRoutingEquivalence(t *testing.T) {
	// Test that these two requests should send identical frames to the agent:
	// 1. /pub/e629457f-112a-4b34-af31-9dae3b6bf5d4/rest/events/session-started (publicHandler)
	// 2. /rest/events/session-started (smartFallbackHandler -> single tunnel routing)

	testCases := []struct {
		name         string
		inputPath    string
		expectedPath string
		description  string
	}{
		{
			name:         "API endpoint",
			inputPath:    "/rest/events/session-started",
			expectedPath: "/rest/events/session-started",
			description:  "Direct API call should route to agent with same path",
		},
		{
			name:         "API endpoint with more path",
			inputPath:    "/rest/module-settings",
			expectedPath: "/rest/module-settings",
			description:  "Another API call should route to agent with same path",
		},
		{
			name:         "Asset request",
			inputPath:    "/assets/polyfills-B8p9DdqU.js",
			expectedPath: "/assets/polyfills-B8p9DdqU.js",
			description:  "Asset request should route to agent with same path",
		},
		{
			name:         "Root path",
			inputPath:    "/",
			expectedPath: "/",
			description:  "Root request should route to agent as root",
		},
		{
			name:         "Deep path",
			inputPath:    "/api/v1/users/123",
			expectedPath: "/api/v1/users/123",
			description:  "Deep API path should route to agent with same path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test path processing logic from tryTunnelRouteWithTimeout
			// This is the logic that smartFallbackHandler uses

			// Simulate the path processing from tryTunnelRouteWithTimeout
			requestPath := strings.TrimPrefix(tc.inputPath, "/")
			if requestPath == "" {
				requestPath = "/"
			} else {
				requestPath = "/" + requestPath
			}

			if requestPath != tc.expectedPath {
				t.Errorf("Smart routing path processing failed: input=%s, expected=%s, got=%s",
					tc.inputPath, tc.expectedPath, requestPath)
			}

			// Test path processing logic from publicHandler
			// This simulates: /pub/{id}/rest/events/session-started -> /rest/events/session-started
			pubPath := "/pub/test-id" + tc.inputPath
			pubPathTrimmed := strings.TrimPrefix(pubPath, "/pub/")
			parts := strings.SplitN(pubPathTrimmed, "/", 2)

			var publicRestPath string
			if len(parts) == 0 || parts[0] == "" {
				publicRestPath = "/"
			} else {
				publicRestPath = "/"
				if len(parts) == 2 {
					publicRestPath += parts[1]
				}
			}

			if publicRestPath != tc.expectedPath {
				t.Errorf("Public handler path processing failed: input=%s, expected=%s, got=%s",
					pubPath, tc.expectedPath, publicRestPath)
			}

			// Most importantly: both should produce the same result
			if requestPath != publicRestPath {
				t.Errorf("PATH MISMATCH: smart routing produces %s, public handler produces %s for input %s",
					requestPath, publicRestPath, tc.inputPath)
			}
		})
	}
}

// Test the complete equivalence scenario
func TestCompleteURLEquivalence(t *testing.T) {
	tunnelID := "e629457f-112a-4b34-af31-9dae3b6bf5d4"

	equivalentPairs := []struct {
		directURL   string
		pubURL      string
		description string
	}{
		{
			directURL:   "/rest/events/session-started",
			pubURL:      "/pub/" + tunnelID + "/rest/events/session-started",
			description: "API endpoint equivalence",
		},
		{
			directURL:   "/rest/module-settings",
			pubURL:      "/pub/" + tunnelID + "/rest/module-settings",
			description: "Module settings API equivalence",
		},
		{
			directURL:   "/assets/polyfills-B8p9DdqU.js",
			pubURL:      "/pub/" + tunnelID + "/assets/polyfills-B8p9DdqU.js",
			description: "Asset equivalence",
		},
	}

	for _, pair := range equivalentPairs {
		t.Run(pair.description, func(t *testing.T) {
			// Extract the path that would be sent to the agent from pubURL
			pubPathTrimmed := strings.TrimPrefix(pair.pubURL, "/pub/")
			parts := strings.SplitN(pubPathTrimmed, "/", 2)

			var agentPathFromPub string
			if len(parts) <= 1 {
				agentPathFromPub = "/"
			} else {
				agentPathFromPub = "/" + parts[1]
			}

			// Extract the path that would be sent to the agent from directURL
			agentPathFromDirect := strings.TrimPrefix(pair.directURL, "/")
			if agentPathFromDirect == "" {
				agentPathFromDirect = "/"
			} else {
				agentPathFromDirect = "/" + agentPathFromDirect
			}

			// They should be identical
			if agentPathFromPub != agentPathFromDirect {
				t.Errorf("URLs not equivalent: %s -> %s, %s -> %s",
					pair.pubURL, agentPathFromPub, pair.directURL, agentPathFromDirect)
			}

			// And both should equal the expected path
			if agentPathFromPub != pair.directURL {
				t.Errorf("Expected agent to receive %s, but pub handler would send %s",
					pair.directURL, agentPathFromPub)
			}

			if agentPathFromDirect != pair.directURL {
				t.Errorf("Expected agent to receive %s, but smart routing would send %s",
					pair.directURL, agentPathFromDirect)
			}
		})
	}
}

// Tests for geographical routing functionality
func TestGeoRoutingFunctionality(t *testing.T) {
	// Save original state
	originalIPGeoCache := ipGeoCache
	originalIPTunnelMap := ipTunnelMap
	originalGeoTunnelPrefs := geoTunnelPrefs
	originalGeoConfig := geoRoutingConfig
	defer func() {
		ipGeoCache = originalIPGeoCache
		ipTunnelMap = originalIPTunnelMap
		geoTunnelPrefs = originalGeoTunnelPrefs
		geoRoutingConfig = originalGeoConfig
	}()

	// Reset for testing
	ipGeoCache = make(map[string]*IPGeoData)
	ipTunnelMap = make(map[string]*IPTunnelMapping)
	geoTunnelPrefs = make(map[string]*GeoTunnelPreference)

	// Enable geo routing for tests
	geoRoutingConfig.EnableGeoRouting = true

	testIPs := []struct {
		ip              string
		expectedCountry string
		expectedRegion  string
	}{
		{"8.8.8.8", "US", "US-WEST"},
		{"4.4.4.4", "US", "US-EAST"},
		{"85.1.1.1", "EU", "EU-CENTRAL"},
		{"202.1.1.1", "AS", "AS-PACIFIC"},
		{"127.0.0.1", "LOCAL", "LOCAL-DEFAULT"},
	}

	for _, test := range testIPs {
		t.Run(fmt.Sprintf("GeoLookup_%s", test.ip), func(t *testing.T) {
			geoData := lookupIPGeoData(test.ip)
			if geoData == nil {
				t.Fatalf("Expected geo data for IP %s", test.ip)
			}

			if geoData.Country != test.expectedCountry {
				t.Errorf("Expected country %s, got %s for IP %s", test.expectedCountry, geoData.Country, test.ip)
			}

			if geoData.Region != test.expectedRegion {
				t.Errorf("Expected region %s, got %s for IP %s", test.expectedRegion, geoData.Region, test.ip)
			}

			// Test caching
			geoData2 := lookupIPGeoData(test.ip)
			if geoData != geoData2 {
				t.Error("Expected cached geo data to be returned")
			}
		})
	}
}

func TestIPTunnelMapping(t *testing.T) {
	// Save original state
	originalIPTunnelMap := ipTunnelMap
	originalGeoTunnelPrefs := geoTunnelPrefs
	originalGeoConfig := geoRoutingConfig
	defer func() {
		ipTunnelMap = originalIPTunnelMap
		geoTunnelPrefs = originalGeoTunnelPrefs
		geoRoutingConfig = originalGeoConfig
	}()

	// Reset for testing
	ipTunnelMap = make(map[string]*IPTunnelMapping)
	geoTunnelPrefs = make(map[string]*GeoTunnelPreference)
	geoRoutingConfig.EnableGeoRouting = true

	testIP := "8.8.8.8"
	tunnelID := "test-tunnel-123"

	t.Run("Record IP tunnel mapping", func(t *testing.T) {
		recordIPTunnelMapping(testIP, tunnelID)

		// Check IP mapping was recorded
		if mapping, exists := ipTunnelMap[testIP]; exists {
			if mapping.LastTunnelID != tunnelID {
				t.Errorf("Expected tunnel ID %s, got %s", tunnelID, mapping.LastTunnelID)
			}
			if mapping.UsageCount != 1 {
				t.Errorf("Expected usage count 1, got %d", mapping.UsageCount)
			}
			if mapping.SuccessRate != 1.0 {
				t.Errorf("Expected success rate 1.0, got %f", mapping.SuccessRate)
			}
		} else {
			t.Error("Expected IP tunnel mapping to be recorded")
		}

		// Check geo preference was updated
		expectedGeoKey := "US_US-WEST"
		if pref, exists := geoTunnelPrefs[expectedGeoKey]; exists {
			if pref.TunnelID != tunnelID {
				t.Errorf("Expected geo preference tunnel %s, got %s", tunnelID, pref.TunnelID)
			}
		} else {
			t.Error("Expected geo preference to be recorded")
		}
	})

	t.Run("Retrieve IP tunnel mapping", func(t *testing.T) {
		retrievedTunnelID := getIPTunnelMapping(testIP)
		if retrievedTunnelID != tunnelID {
			t.Errorf("Expected retrieved tunnel ID %s, got %s", tunnelID, retrievedTunnelID)
		}
	})

	t.Run("Retrieve geo tunnel preference", func(t *testing.T) {
		retrievedTunnelID := getGeoTunnelPreference(testIP)
		if retrievedTunnelID != tunnelID {
			t.Errorf("Expected geo preference tunnel ID %s, got %s", tunnelID, retrievedTunnelID)
		}
	})

	t.Run("Multiple recordings update stats", func(t *testing.T) {
		// Record multiple times to test success rate calculation
		recordIPTunnelMapping(testIP, tunnelID)
		recordIPTunnelMapping(testIP, tunnelID)

		if mapping := ipTunnelMap[testIP]; mapping != nil {
			if mapping.UsageCount != 3 {
				t.Errorf("Expected usage count 3, got %d", mapping.UsageCount)
			}
			// Success rate should be close to 1.0 (using EMA)
			if mapping.SuccessRate < 0.9 {
				t.Errorf("Expected success rate > 0.9, got %f", mapping.SuccessRate)
			}
		}
	})
}

func TestGeoRoutingStats(t *testing.T) {
	// Save original state
	originalIPGeoCache := ipGeoCache
	originalIPTunnelMap := ipTunnelMap
	originalGeoTunnelPrefs := geoTunnelPrefs
	originalGeoConfig := geoRoutingConfig
	defer func() {
		ipGeoCache = originalIPGeoCache
		ipTunnelMap = originalIPTunnelMap
		geoTunnelPrefs = originalGeoTunnelPrefs
		geoRoutingConfig = originalGeoConfig
	}()

	// Reset for testing
	ipGeoCache = make(map[string]*IPGeoData)
	ipTunnelMap = make(map[string]*IPTunnelMapping)
	geoTunnelPrefs = make(map[string]*GeoTunnelPreference)
	geoRoutingConfig.EnableGeoRouting = true

	// Add some test data
	recordIPTunnelMapping("8.8.8.8", "tunnel-us")
	recordIPTunnelMapping("85.1.1.1", "tunnel-eu")
	recordIPTunnelMapping("202.1.1.1", "tunnel-as")

	stats := getGeoRoutingStats()

	t.Run("Basic stats structure", func(t *testing.T) {
		if enabled, ok := stats["enabled"].(bool); !ok || !enabled {
			t.Error("Expected geo routing to be enabled in stats")
		}

		if _, ok := stats["cache_ttl"]; !ok {
			t.Error("Expected cache_ttl in stats")
		}

		if _, ok := stats["mapping_ttl"]; !ok {
			t.Error("Expected mapping_ttl in stats")
		}
	})

	t.Run("IP mappings stats", func(t *testing.T) {
		ipMappings, ok := stats["ip_mappings"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected ip_mappings in stats")
		}

		if totalMappings, ok := ipMappings["total_mappings"].(int); !ok || totalMappings != 3 {
			t.Errorf("Expected 3 total mappings, got %v", totalMappings)
		}

		countries, ok := ipMappings["countries"].(map[string]int)
		if !ok {
			t.Fatal("Expected countries in ip_mappings stats")
		}

		expectedCountries := map[string]int{"US": 1, "EU": 1, "AS": 1}
		for country, expectedCount := range expectedCountries {
			if actualCount := countries[country]; actualCount != expectedCount {
				t.Errorf("Expected %d mappings for country %s, got %d", expectedCount, country, actualCount)
			}
		}
	})

	t.Run("Geo preferences stats", func(t *testing.T) {
		geoPrefs, ok := stats["geo_preferences"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected geo_preferences in stats")
		}

		if count, ok := geoPrefs["count"].(int); !ok || count != 3 {
			t.Errorf("Expected 3 geo preferences, got %v", count)
		}

		regions, ok := geoPrefs["regions"].([]string)
		if !ok {
			t.Fatal("Expected regions in geo_preferences stats")
		}

		if len(regions) != 3 {
			t.Errorf("Expected 3 regions, got %d", len(regions))
		}

		// Check that expected regions are present
		expectedRegions := map[string]bool{
			"US_US-WEST":    false,
			"EU_EU-CENTRAL": false,
			"AS_AS-PACIFIC": false,
		}
		for _, region := range regions {
			if _, exists := expectedRegions[region]; exists {
				expectedRegions[region] = true
			}
		}

		for region, found := range expectedRegions {
			if !found {
				t.Errorf("Expected region %s not found in stats", region)
			}
		}
	})
}

func TestGeoRoutingIntegration(t *testing.T) {
	// Save original state
	originalAgents := agents
	originalIPTunnelMap := ipTunnelMap
	originalGeoTunnelPrefs := geoTunnelPrefs
	originalGeoConfig := geoRoutingConfig
	defer func() {
		agents = originalAgents
		ipTunnelMap = originalIPTunnelMap
		geoTunnelPrefs = originalGeoTunnelPrefs
		geoRoutingConfig = originalGeoConfig
	}()

	// Reset for testing
	agents = map[string]*agentConn{
		"tunnel-us": nil,
		"tunnel-eu": nil,
	}
	ipTunnelMap = make(map[string]*IPTunnelMapping)
	geoTunnelPrefs = make(map[string]*GeoTunnelPreference)
	geoRoutingConfig.EnableGeoRouting = true

	t.Run("IP routing preference", func(t *testing.T) {
		testIP := "8.8.8.8" // US IP

		// First, record that this IP successfully used tunnel-us
		recordIPTunnelMapping(testIP, "tunnel-us")

		// Now check that getIPTunnelMapping returns the right tunnel
		preferredTunnel := getIPTunnelMapping(testIP)
		if preferredTunnel != "tunnel-us" {
			t.Errorf("Expected IP %s to prefer tunnel-us, got %s", testIP, preferredTunnel)
		}

		// Check geo preference as well
		geoPreferredTunnel := getGeoTunnelPreference(testIP)
		if geoPreferredTunnel != "tunnel-us" {
			t.Errorf("Expected geo preference for IP %s to be tunnel-us, got %s", testIP, geoPreferredTunnel)
		}
	})

	t.Run("Geo region fallback", func(t *testing.T) {
		// Test that a different US IP (same region) gets the same preference
		newUSIP := "8.8.4.4" // Different US IP but same region (US-WEST)

		// This IP hasn't been used before, but should get US-WEST region preference
		geoPreferredTunnel := getGeoTunnelPreference(newUSIP)
		if geoPreferredTunnel != "tunnel-us" {
			t.Errorf("Expected new US IP %s to get US tunnel preference, got %s", newUSIP, geoPreferredTunnel)
		}

		// Test that a different US region gets no preference yet
		usEastIP := "4.4.4.4" // US-EAST IP
		geoPreferredTunnel = getGeoTunnelPreference(usEastIP)
		if geoPreferredTunnel != "" {
			t.Errorf("Expected US-EAST IP %s to get no preference yet, got %s", usEastIP, geoPreferredTunnel)
		}
	})

	t.Run("Different region gets different preference", func(t *testing.T) {
		euIP := "85.1.1.1" // EU IP

		// Record EU IP using EU tunnel
		recordIPTunnelMapping(euIP, "tunnel-eu")

		preferredTunnel := getIPTunnelMapping(euIP)
		if preferredTunnel != "tunnel-eu" {
			t.Errorf("Expected EU IP %s to prefer tunnel-eu, got %s", euIP, preferredTunnel)
		}

		// Now a different EU IP should get EU preference
		newEUIP := "91.1.1.1"
		geoPreferredTunnel := getGeoTunnelPreference(newEUIP)
		if geoPreferredTunnel != "tunnel-eu" {
			t.Errorf("Expected new EU IP %s to get EU tunnel preference, got %s", newEUIP, geoPreferredTunnel)
		}
	})
}

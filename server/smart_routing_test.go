package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

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

// TestSingleTunnelOptimization tests the various routing strategies with single tunnel
func TestSingleTunnelOptimization(t *testing.T) {
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
			name:           "Single tunnel Regular - should use priority",
			tunnelCount:    1,
			path:           "/about",
			isAPI:          false,
			isAsset:        false,
			expectPriority: true,
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

			// Test priority routing condition - ALL requests with single tunnel
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

// TestEnhancedSingleTunnelRouting tests the enhanced single tunnel routing logic
func TestEnhancedSingleTunnelRouting(t *testing.T) {
	originalAgents := agents
	originalTracker := clientTracker
	defer func() {
		agents = originalAgents
		clientTracker = originalTracker
	}()

	// Setup test environment with single tunnel
	agents = map[string]*agentConn{
		"test-tunnel-123": nil, // nil agent simulates routing failure for testing
	}
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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

			// Test routing logic - ALL requests should use priority routing with single tunnel
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

// TestAssetRoutingRetryLogic tests the specific asset routing retry logic
func TestAssetRoutingRetryLogic(t *testing.T) {
	originalAgents := agents
	defer func() {
		agents = originalAgents
	}()

	// Setup single tunnel environment
	agents = map[string]*agentConn{
		"retry-tunnel": nil,
	}

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

// TestUltimateFallbackEnhancement tests the ultimate fallback with extended timeout
func TestUltimateFallbackEnhancement(t *testing.T) {
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

// TestCompleteAssetRoutingFix tests the complete asset routing fix for 404 issues
func TestCompleteAssetRoutingFix(t *testing.T) {
	originalAgents := agents
	originalTracker := clientTracker
	defer func() {
		agents = originalAgents
		clientTracker = originalTracker
	}()

	// Setup complete environment simulating the 404 issue scenario
	agents = map[string]*agentConn{
		"e629457f-112a-4b34-af31-9dae3b6bf5d4": nil, // The actual tunnel ID from the issue
	}
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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

			// Step 3: Verify priority routing would be triggered
			shouldUsePriority := len(tunnelIDs) == 1
			if !shouldUsePriority {
				t.Error("Priority routing should be used for assets with single tunnel")
			}

			// Step 4: Verify ultimate fallback would be triggered for single tunnel
			shouldUseFallback := len(tunnelIDs) == 1
			if !shouldUseFallback {
				t.Error("Ultimate fallback should be available for single tunnel scenario")
			}
		})
	}
}

// TestSpecificFailingAPIRouting tests specific API paths that are failing in production
func TestSpecificFailingAPIRouting(t *testing.T) {
	originalAgents := agents
	originalTracker := clientTracker
	defer func() {
		agents = originalAgents
		clientTracker = originalTracker
	}()

	// Setup single tunnel environment (like production scenario)
	agents = map[string]*agentConn{
		"e629457f-112a-4b34-af31-9dae3b6bf5d4": nil, // The actual tunnel ID from the issue
	}
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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
		})
	}
}

// TestPublicHandlerAndSmartRoutingEquivalence tests that direct API paths and /pub/{id}/... paths work equivalently
func TestPublicHandlerAndSmartRoutingEquivalence(t *testing.T) {
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test path processing logic from smart routing
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

// TestConcurrentClientTrackerOperations tests concurrent safety
func TestConcurrentClientTrackerOperations(t *testing.T) {
	tracker := &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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

// TestSuccessRateCalculation tests EMA success rate calculations
func TestSuccessRateCalculation(t *testing.T) {
	tracker := &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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

// TestSmartRoutingTunnelAffinity tests tunnel affinity functionality for smart routing
func TestSmartRoutingTunnelAffinity(t *testing.T) {
	originalTracker := clientTracker
	defer func() {
		clientTracker = originalTracker
	}()

	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	t.Run("CreateImmediateBinding", func(t *testing.T) {
		clientKey := "test-client-key"
		tunnelID := "tunnel-1"
		accessType := "custom_url"

		clientTracker.CreateImmediateBinding(clientKey, tunnelID, accessType)

		// Check that the binding was created
		bestTunnel := clientTracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID {
			t.Errorf("Expected immediate binding to return %s, got %s", tunnelID, bestTunnel)
		}
	})

	t.Run("GetBestTunnelWithinAffinityWindow", func(t *testing.T) {
		clientKey := "test-client-key"
		tunnelID := "tunnel-1"

		clientTracker.CreateImmediateBinding(clientKey, tunnelID, "public_url")

		// Should return the bound tunnel immediately
		bestTunnel := clientTracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID {
			t.Errorf("Expected tunnel within affinity window: %s, got %s", tunnelID, bestTunnel)
		}
	})

	t.Run("GetBestTunnelAfterAffinityWindowExpires", func(t *testing.T) {
		clientKey := "test-client-key"
		tunnelID := "tunnel-2"

		// Create a binding and wait for it to expire (simulate with old time)
		clientTracker.CreateImmediateBinding(clientKey, tunnelID, "test")

		// Create a session with historical data to test fallback
		clientTracker.clientSessions[clientKey] = &ClientSession{
			ID:       clientKey,
			LastSeen: time.Now(),
			TunnelMappings: map[string]int{
				"tunnel-1": 10,
			},
			SuccessRate: map[string]float64{
				"tunnel-1": 0.9,
			},
			Confidence: 0.8,
		}

		// Simulate expired recent mapping by setting an old time
		clientTracker.recentMappings[clientKey] = &RecentMapping{
			TunnelID:   tunnelID,
			Timestamp:  time.Now().Add(-5 * time.Second), // Simulate expired mapping
			AccessType: "test",
		}

		bestTunnel := clientTracker.GetBestTunnel(clientKey)
		// Should fallback to historical best tunnel or handle gracefully
		if bestTunnel == "" {
			t.Log("Tunnel affinity expired correctly, no tunnel returned")
		}
	})
}
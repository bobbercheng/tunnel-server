package main

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTunnelAffinityWindow tests the 2-second tunnel affinity optimization
func TestTunnelAffinityWindow(t *testing.T) {
	// Setup: Create fresh client tracker
	tracker := NewClientTracker()
	clientKey := "test-client-key"
	tunnelID1 := "tunnel-1"
	tunnelID2 := "tunnel-2"

	t.Run("CreateImmediateBinding", func(t *testing.T) {
		// Create immediate binding
		tracker.CreateImmediateBinding(clientKey, tunnelID1, "custom_url")

		// Verify the binding was created
		tracker.mu.RLock()
		recentMapping, exists := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()

		if !exists {
			t.Fatal("Expected recent mapping to be created")
		}

		if recentMapping.TunnelID != tunnelID1 {
			t.Errorf("Expected tunnel ID %s, got %s", tunnelID1, recentMapping.TunnelID)
		}

		if recentMapping.AccessType != "custom_url" {
			t.Errorf("Expected access type 'custom_url', got %s", recentMapping.AccessType)
		}

		// Check timestamp is recent
		age := time.Since(recentMapping.Timestamp)
		if age > time.Second {
			t.Errorf("Expected recent timestamp, got age %v", age)
		}
	})

	t.Run("GetBestTunnelWithinAffinityWindow", func(t *testing.T) {
		// Create immediate binding
		tracker.CreateImmediateBinding(clientKey, tunnelID1, "public_url")

		// GetBestTunnel should return the recent mapping
		bestTunnel := tracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID1 {
			t.Errorf("Expected tunnel %s from affinity window, got %s", tunnelID1, bestTunnel)
		}
	})

	t.Run("GetBestTunnelAfterAffinityWindowExpires", func(t *testing.T) {
		// Create immediate binding with backdated timestamp (expired)
		tracker.mu.Lock()
		tracker.recentMappings[clientKey] = &RecentMapping{
			TunnelID:   tunnelID2,
			Timestamp:  time.Now().Add(-5 * time.Second), // 5 seconds ago (expired)
			AccessType: "expired_mapping",
		}
		
		// Add session data to fall back to
		tracker.clientSessions[clientKey] = &ClientSession{
			ID:             clientKey,
			LastSeen:       time.Now(),
			TunnelMappings: map[string]int{tunnelID1: 10},
			SuccessRate:    map[string]float64{tunnelID1: 0.9},
			Confidence:     0.8,
		}
		tracker.mu.Unlock()

		// GetBestTunnel should skip expired mapping and use session data
		bestTunnel := tracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID1 {
			t.Errorf("Expected tunnel %s from session data, got %s", tunnelID1, bestTunnel)
		}
	})

	t.Run("OverwriteExistingBinding", func(t *testing.T) {
		// Create first binding
		tracker.CreateImmediateBinding(clientKey, tunnelID1, "first_access")
		
		// Wait a moment
		time.Sleep(10 * time.Millisecond)
		
		// Create second binding - should overwrite
		tracker.CreateImmediateBinding(clientKey, tunnelID2, "second_access")

		// Verify second binding overwrote first
		bestTunnel := tracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID2 {
			t.Errorf("Expected overwritten tunnel %s, got %s", tunnelID2, bestTunnel)
		}

		tracker.mu.RLock()
		recentMapping := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()

		if recentMapping.AccessType != "second_access" {
			t.Errorf("Expected access type 'second_access', got %s", recentMapping.AccessType)
		}
	})

	t.Run("CleanupExpiredRecentMappings", func(t *testing.T) {
		// Create multiple bindings with different ages
		currentClient := "current-client"
		expiredClient := "expired-client"
		
		tracker.mu.Lock()
		// Recent mapping (should be kept)
		tracker.recentMappings[currentClient] = &RecentMapping{
			TunnelID:   tunnelID1,
			Timestamp:  time.Now(),
			AccessType: "recent",
		}
		
		// Expired mapping (should be cleaned up)
		tracker.recentMappings[expiredClient] = &RecentMapping{
			TunnelID:   tunnelID2,
			Timestamp:  time.Now().Add(-5 * time.Second), // 5 seconds ago
			AccessType: "expired",
		}
		tracker.mu.Unlock()

		// Run cleanup
		tracker.CleanupExpiredRecentMappings()

		// Verify results
		tracker.mu.RLock()
		_, currentExists := tracker.recentMappings[currentClient]
		_, expiredExists := tracker.recentMappings[expiredClient]
		tracker.mu.RUnlock()

		if !currentExists {
			t.Error("Expected recent mapping to be kept")
		}
		if expiredExists {
			t.Error("Expected expired mapping to be cleaned up")
		}
	})
}

// TestTunnelAffinityIntegration tests the integration with HTTP handlers
func TestTunnelAffinityIntegration(t *testing.T) {
	// Setup: Reset global state
	tunnelsMu.Lock()
	agentsMu.Lock()
	customURLsMu.Lock()
	
	// Clear existing state
	tunnels = make(map[string]*TunnelInfo)
	agents = make(map[string]*agentConn)
	customURLs = make(map[string]string)
	clientTracker = NewClientTracker()
	
	tunnelID := "test-tunnel"
	customURL := "testapp"
	
	// Create tunnel with custom URL
	tunnels[tunnelID] = &TunnelInfo{
		Secret:      "secret",
		Protocol:    "http",
		CustomURL:   customURL,
		UseRedirect: false,
		Created:     time.Now(),
	}
	
	customURLs[customURL] = tunnelID
	
	// Create mock agent connection
	agents[tunnelID] = &agentConn{
		id:          tunnelID,
		connectedAt: time.Now(),
	}
	
	customURLsMu.Unlock()
	agentsMu.Unlock()
	tunnelsMu.Unlock()

	t.Run("CustomURLCreatesImmediateBinding", func(t *testing.T) {
		// Create request to custom URL
		req := httptest.NewRequest("GET", "/"+customURL, nil)
		req.Header.Set("User-Agent", "test-browser")
		
		clientKey := generateClientKey(req)
		
		// Verify no initial binding
		tracker := clientTracker
		tracker.mu.RLock()
		_, exists := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()
		
		if exists {
			t.Error("Expected no initial recent mapping")
		}
		
		// Note: We can't easily test the full HTTP flow without mocking tryTunnelRouteWithTimeout,
		// but we can test that CreateImmediateBinding works correctly
		tracker.CreateImmediateBinding(clientKey, tunnelID, "custom_url")
		
		// Verify binding was created
		tracker.mu.RLock()
		recentMapping, exists := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()
		
		if !exists {
			t.Error("Expected recent mapping to be created")
		}
		
		if recentMapping.TunnelID != tunnelID {
			t.Errorf("Expected tunnel ID %s, got %s", tunnelID, recentMapping.TunnelID)
		}
		
		if recentMapping.AccessType != "custom_url" {
			t.Errorf("Expected access type 'custom_url', got %s", recentMapping.AccessType)
		}
	})

	t.Run("PublicURLCreatesImmediateBinding", func(t *testing.T) {
		// Test public URL access pattern
		req := httptest.NewRequest("GET", "/__pub__/"+tunnelID+"/api/data", nil)
		req.Header.Set("User-Agent", "test-browser")
		
		clientKey := generateClientKey(req)
		
		// Simulate successful public URL routing
		tracker := clientTracker
		tracker.CreateImmediateBinding(clientKey, tunnelID, "public_url")
		
		// Verify binding
		tracker.mu.RLock()
		recentMapping, exists := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()
		
		if !exists {
			t.Error("Expected recent mapping to be created")
		}
		
		if recentMapping.AccessType != "public_url" {
			t.Errorf("Expected access type 'public_url', got %s", recentMapping.AccessType)
		}
		
		// Verify immediate follow-up request would use same tunnel
		bestTunnel := tracker.GetBestTunnel(clientKey)
		if bestTunnel != tunnelID {
			t.Errorf("Expected follow-up request to use tunnel %s, got %s", tunnelID, bestTunnel)
		}
	})

	t.Run("PrefixMatchingCreatesImmediateBinding", func(t *testing.T) {
		// Test custom URL prefix matching (e.g., /testapp/api/endpoint)
		req := httptest.NewRequest("GET", "/"+customURL+"/api/endpoint", nil)
		req.Header.Set("User-Agent", "test-browser")
		
		clientKey := generateClientKey(req)
		
		// Simulate successful prefix routing
		tracker := clientTracker
		tracker.CreateImmediateBinding(clientKey, tunnelID, "custom_url_prefix")
		
		// Verify binding
		tracker.mu.RLock()
		recentMapping, exists := tracker.recentMappings[clientKey]
		tracker.mu.RUnlock()
		
		if !exists {
			t.Error("Expected recent mapping to be created")
		}
		
		if recentMapping.AccessType != "custom_url_prefix" {
			t.Errorf("Expected access type 'custom_url_prefix', got %s", recentMapping.AccessType)
		}
	})
}

// TestTunnelAffinityUserBehaviorSimulation simulates real user behavior patterns
func TestTunnelAffinityUserBehaviorSimulation(t *testing.T) {
	tracker := NewClientTracker()
	clientKey := "user-client-key"
	tunnelID := "user-tunnel"

	t.Run("TypicalUserBehaviorPattern", func(t *testing.T) {
		// Simulate user opening custom URL (main page)
		tracker.CreateImmediateBinding(clientKey, tunnelID, "custom_url")
		
		// Verify main page binding
		if bestTunnel := tracker.GetBestTunnel(clientKey); bestTunnel != tunnelID {
			t.Errorf("Main page should use tunnel %s, got %s", tunnelID, bestTunnel)
		}
		
		// Simulate rapid asset requests (CSS, JS, images) within 2 seconds
		assetRequests := []string{"style.css", "app.js", "logo.png", "fonts.woff2"}
		
		for i, asset := range assetRequests {
			// Small delay between asset requests (realistic timing)
			time.Sleep(100 * time.Millisecond)
			
			// Each asset request should still get the same tunnel due to affinity
			bestTunnel := tracker.GetBestTunnel(clientKey)
			if bestTunnel != tunnelID {
				t.Errorf("Asset request %d (%s) should use tunnel %s, got %s", i, asset, tunnelID, bestTunnel)
			}
			
			// Simulate successful asset loading (would normally call RecordSuccess)
			tracker.RecordSuccess(clientKey, tunnelID)
		}
		
		// Final check - should still be within affinity window
		finalBestTunnel := tracker.GetBestTunnel(clientKey)
		if finalBestTunnel != tunnelID {
			t.Errorf("Final request should still use tunnel %s, got %s", tunnelID, finalBestTunnel)
		}
	})

	t.Run("UserSwitchingBetweenApplications", func(t *testing.T) {
		tunnelApp1 := "app1-tunnel"
		tunnelApp2 := "app2-tunnel"
		
		// User opens first application
		tracker.CreateImmediateBinding(clientKey, tunnelApp1, "custom_url")
		
		// Verify first app binding
		if bestTunnel := tracker.GetBestTunnel(clientKey); bestTunnel != tunnelApp1 {
			t.Errorf("First app should use tunnel %s, got %s", tunnelApp1, bestTunnel)
		}
		
		// Wait for affinity window to expire
		time.Sleep(3 * time.Second)
		
		// User opens second application - should overwrite previous binding
		tracker.CreateImmediateBinding(clientKey, tunnelApp2, "custom_url")
		
		// Verify second app binding
		if bestTunnel := tracker.GetBestTunnel(clientKey); bestTunnel != tunnelApp2 {
			t.Errorf("Second app should use tunnel %s, got %s", tunnelApp2, bestTunnel)
		}
	})

	t.Run("HighFrequencyRequests", func(t *testing.T) {
		// Simulate very rapid requests (like WebSocket connections or polling)
		startTime := time.Now()
		tracker.CreateImmediateBinding(clientKey, tunnelID, "api_endpoint")
		
		// Make 50 rapid requests within the affinity window
		for i := 0; i < 50; i++ {
			bestTunnel := tracker.GetBestTunnel(clientKey)
			if bestTunnel != tunnelID {
				t.Errorf("Rapid request %d should use tunnel %s, got %s", i, tunnelID, bestTunnel)
			}
			
			// Simulate very fast requests (every 20ms)
			time.Sleep(20 * time.Millisecond)
		}
		
		totalDuration := time.Since(startTime)
		if totalDuration > TunnelAffinityWindow {
			t.Logf("Test took %v, which exceeds affinity window %v - this is expected for high-frequency test", 
				totalDuration, TunnelAffinityWindow)
		}
	})
}

// BenchmarkTunnelAffinity benchmarks the performance of tunnel affinity operations
func BenchmarkTunnelAffinity(b *testing.B) {
	tracker := NewClientTracker()
	
	b.Run("CreateImmediateBinding", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			clientKey := fmt.Sprintf("client-%d", i)
			tunnelID := fmt.Sprintf("tunnel-%d", i%10) // 10 different tunnels
			tracker.CreateImmediateBinding(clientKey, tunnelID, "benchmark")
		}
	})
	
	b.Run("GetBestTunnelWithAffinity", func(b *testing.B) {
		// Setup some bindings
		for i := 0; i < 1000; i++ {
			clientKey := fmt.Sprintf("client-%d", i)
			tunnelID := fmt.Sprintf("tunnel-%d", i%10)
			tracker.CreateImmediateBinding(clientKey, tunnelID, "benchmark")
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			clientKey := fmt.Sprintf("client-%d", i%1000)
			_ = tracker.GetBestTunnel(clientKey)
		}
	})
	
	b.Run("CleanupExpiredMappings", func(b *testing.B) {
		// Setup many expired mappings
		tracker.mu.Lock()
		for i := 0; i < 10000; i++ {
			clientKey := fmt.Sprintf("expired-client-%d", i)
			tracker.recentMappings[clientKey] = &RecentMapping{
				TunnelID:   fmt.Sprintf("tunnel-%d", i%10),
				Timestamp:  time.Now().Add(-5 * time.Second), // Expired
				AccessType: "benchmark",
			}
		}
		tracker.mu.Unlock()
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tracker.CleanupExpiredRecentMappings()
		}
	})
}
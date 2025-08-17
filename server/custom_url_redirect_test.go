package main

import (
	"testing"
	"time"
)

func TestStrictRoutingWithRedirectSession(t *testing.T) {
	// Setup: Reset global state
	tunnelsMu.Lock()
	agentsMu.Lock()
	customURLsMu.Lock()
	
	// Clear existing state
	tunnels = make(map[string]*TunnelInfo)
	agents = make(map[string]*agentConn)
	customURLs = make(map[string]string)
	clientTracker = NewClientTracker()
	
	// Create two tunnels
	tunnel1ID := "tunnel-1"
	tunnel2ID := "tunnel-2"
	
	// Tunnel 1 has custom URL with redirect
	tunnels[tunnel1ID] = &TunnelInfo{
		Secret:      "secret1",
		Protocol:    "http",
		CustomURL:   "librechat",
		UseRedirect: true,
		Created:     time.Now(),
	}
	
	// Tunnel 2 has no custom URL
	tunnels[tunnel2ID] = &TunnelInfo{
		Secret:   "secret2",
		Protocol: "http",
		Created:  time.Now(),
	}
	
	// Register custom URL mapping
	customURLs["librechat"] = tunnel1ID
	
	// Create mock agent connections
	agents[tunnel1ID] = &agentConn{
		id:          tunnel1ID,
		connectedAt: time.Now(),
	}
	agents[tunnel2ID] = &agentConn{
		id:          tunnel2ID,
		connectedAt: time.Now(),
	}
	
	customURLsMu.Unlock()
	agentsMu.Unlock()
	tunnelsMu.Unlock()
	
	t.Run("RedirectSessionEnforcesStrictRouting", func(t *testing.T) {
		clientKey := "test-client-strict-routing"
		customURL := "librechat"
		tunnelID := tunnel1ID
		
		// Create a redirect session
		createRedirectSession(clientKey, customURL, tunnelID)
		
		// Verify the session exists and is active
		session := getActiveRedirectSession(clientKey)
		if session == nil {
			t.Fatal("Expected to find active redirect session")
		}
		if session.TunnelID != tunnelID {
			t.Errorf("Expected tunnel ID '%s', got '%s'", tunnelID, session.TunnelID)
		}
		if !session.Active {
			t.Error("Expected session to be active")
		}
		
		// Verify that when multiple tunnels exist, we should still have strict routing
		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) != 2 {
			t.Errorf("Expected 2 tunnels, got %d", len(tunnelIDs))
		}
		
		// The key point: even with multiple tunnels, redirect session should be respected
		// This test verifies the session exists and is properly configured
	})
	
	t.Run("RedirectSessionWithSpecificCustomURL", func(t *testing.T) {
		clientKey := "test-client-custom-url"
		customURL := "librechat"
		tunnelID := tunnel1ID
		
		// Create a redirect session
		createRedirectSession(clientKey, customURL, tunnelID)
		
		// Test getting the session by specific custom URL
		session := getActiveRedirectSessionForCustomURL(clientKey, customURL)
		if session == nil {
			t.Error("Expected to find redirect session for specific custom URL")
		} else {
			if session.CustomURL != customURL {
				t.Errorf("Expected custom URL '%s', got '%s'", customURL, session.CustomURL)
			}
			if session.TunnelID != tunnelID {
				t.Errorf("Expected tunnel ID '%s', got '%s'", tunnelID, session.TunnelID)
			}
			if !session.Active {
				t.Error("Expected session to be active")
			}
		}
	})
	
	t.Run("MultipleTunnelScenario", func(t *testing.T) {
		// Verify we have multiple tunnels active
		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) != 2 {
			t.Errorf("Expected 2 tunnels for this test, got %d", len(tunnelIDs))
		}
		
		// Verify tunnel IDs are what we expect
		foundTunnel1 := false
		foundTunnel2 := false
		for _, id := range tunnelIDs {
			if id == tunnel1ID {
				foundTunnel1 = true
			}
			if id == tunnel2ID {
				foundTunnel2 = true
			}
		}
		
		if !foundTunnel1 {
			t.Errorf("Expected to find tunnel1 (%s) in active tunnels: %v", tunnel1ID, tunnelIDs)
		}
		if !foundTunnel2 {
			t.Errorf("Expected to find tunnel2 (%s) in active tunnels: %v", tunnel2ID, tunnelIDs)
		}
		
		// Verify custom URL mapping is correct
		customURLsMu.RLock()
		if mappedTunnelID, exists := customURLs["librechat"]; !exists {
			t.Error("Expected 'librechat' custom URL to be mapped")
		} else if mappedTunnelID != tunnel1ID {
			t.Errorf("Expected 'librechat' to map to '%s', got '%s'", tunnel1ID, mappedTunnelID)
		}
		customURLsMu.RUnlock()
	})
}

func TestSingleTunnelOptimizationStillWorks(t *testing.T) {
	// Setup: Reset global state for single tunnel test
	tunnelsMu.Lock()
	agentsMu.Lock()
	customURLsMu.Lock()
	
	// Clear existing state
	tunnels = make(map[string]*TunnelInfo)
	agents = make(map[string]*agentConn)
	customURLs = make(map[string]string)
	clientTracker = NewClientTracker()
	
	// Create single tunnel with custom URL and redirect
	tunnelID := "single-tunnel"
	tunnels[tunnelID] = &TunnelInfo{
		Secret:      "secret",
		Protocol:    "http",
		CustomURL:   "librechat",
		UseRedirect: true,
		Created:     time.Now(),
	}
	
	customURLs["librechat"] = tunnelID
	agents[tunnelID] = &agentConn{
		id:          tunnelID,
		connectedAt: time.Now(),
	}
	
	customURLsMu.Unlock()
	agentsMu.Unlock()
	tunnelsMu.Unlock()
	
	// Test that single tunnel optimization should still work
	tunnelIDs := getActiveTunnelIDs()
	if len(tunnelIDs) != 1 {
		t.Errorf("Expected 1 tunnel, got %d", len(tunnelIDs))
	}
	
	if len(tunnelIDs) > 0 && tunnelIDs[0] != tunnelID {
		t.Errorf("Expected tunnel ID '%s', got '%s'", tunnelID, tunnelIDs[0])
	}
}
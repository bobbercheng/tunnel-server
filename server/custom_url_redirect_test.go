package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestCustomURLRedirectWithMultipleTunnels(t *testing.T) {
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

	t.Run("DetectCustomURLFromRedirect", func(t *testing.T) {
		// Test 1: Referer-based detection
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Referer", "https://example.com/librechat")

		clientKey := generateClientKey(req)
		detectedURL := detectCustomURLFromRedirect(req, clientKey)

		if detectedURL != "librechat" {
			t.Errorf("Expected to detect 'librechat', got '%s'", detectedURL)
		}

		// Test 2: Non-root path should not detect
		req2 := httptest.NewRequest("GET", "/assets/style.css", nil)
		req2.Header.Set("Referer", "https://example.com/librechat")

		clientKey2 := generateClientKey(req2)
		detectedURL2 := detectCustomURLFromRedirect(req2, clientKey2)

		if detectedURL2 != "" {
			t.Errorf("Expected empty string for non-root path, got '%s'", detectedURL2)
		}
	})

	t.Run("CustomURLFallbackLogic", func(t *testing.T) {
		// Create a request to root that should trigger fallback
		req := httptest.NewRequest("GET", "/", nil)

		// Since we can't easily mock the tunnel routing, we'll test the detection logic
		_ = generateClientKey(req)

		// Verify we can find redirect-enabled custom URLs
		customURLsMu.RLock()
		var redirectCustomURLs []string
		for customURL, tunnelID := range customURLs {
			tunnelsMu.RLock()
			if tunnel, exists := tunnels[tunnelID]; exists && tunnel.UseRedirect {
				redirectCustomURLs = append(redirectCustomURLs, customURL)
			}
			tunnelsMu.RUnlock()
		}
		customURLsMu.RUnlock()

		if len(redirectCustomURLs) != 1 {
			t.Errorf("Expected 1 redirect custom URL, got %d", len(redirectCustomURLs))
		}

		if len(redirectCustomURLs) > 0 && redirectCustomURLs[0] != "librechat" {
			t.Errorf("Expected 'librechat', got '%s'", redirectCustomURLs[0])
		}

		// Test that we can get the tunnel for the custom URL
		tunnelID := getCustomURLTunnel("librechat")
		if tunnelID != tunnel1ID {
			t.Errorf("Expected tunnel ID '%s', got '%s'", tunnel1ID, tunnelID)
		}
	})

	t.Run("RedirectSessionManagement", func(t *testing.T) {
		clientKey := "test-client-key"
		customURL := "librechat"
		tunnelID := tunnel1ID

		// Create a redirect session
		createRedirectSession(clientKey, customURL, tunnelID)

		// Test getting the session
		session := getActiveRedirectSession(clientKey)
		if session == nil {
			t.Error("Expected to find redirect session")
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

		// Test getting any active session
		anySession := getActiveRedirectSession(clientKey)
		if anySession == nil {
			t.Error("Expected to find any active redirect session")
		} else if anySession.CustomURL != customURL {
			t.Errorf("Expected custom URL '%s', got '%s'", customURL, anySession.CustomURL)
		}
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

package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestGeoLocationFeatures(t *testing.T) {
	// Force GeoIP initialization with the test database
	os.Setenv("GEOIP_DB_PATH", "geolite/GeoLite2-City.mmdb")
	initGeoIP()
	
	if geoReader == nil {
		t.Skip("GeoIP database not available, skipping geo location tests")
	}
	
	t.Run("TestIPGeoDataLookup", testIPGeoDataLookup)
	t.Run("TestIPTunnelMappingOperations", testIPTunnelMappingOperations)
	t.Run("TestGeoTunnelPreferences", testGeoTunnelPreferences)
	t.Run("TestGeoRoutingStats", testGeoRoutingStats)
	t.Run("TestGeoRoutingIntegration", testGeoRoutingIntegration)
}

func testIPGeoDataLookup(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectData  bool
		description string
	}{
		{
			name:        "Valid US IP",
			ip:          "8.8.8.8", // Google DNS - US
			expectData:  true,
			description: "Should return geo data for valid US IP",
		},
		{
			name:        "Another valid IP", 
			ip:          "1.1.1.1", // Cloudflare - may return empty geo data
			expectData:  true, // GeoIP library returns structure even for IPs without full data
			description: "Should handle IPs without geo data gracefully",
		},
		{
			name:        "Invalid IP",
			ip:          "invalid-ip",
			expectData:  false,
			description: "Should return nil for invalid IP",
		},
		{
			name:        "Empty IP",
			ip:          "",
			expectData:  false,
			description: "Should return nil for empty IP",
		},
		{
			name:        "Private IP",
			ip:          "192.168.1.1",
			expectData:  true, // GeoIP may return empty data rather than nil for private IPs
			description: "Should return geo data structure even for private IPs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			geoData := lookupIPGeoData(tt.ip)
			
			if tt.expectData {
				if geoData == nil {
					t.Errorf("Expected geo data for IP %s, got nil", tt.ip)
					return
				}
				
				// Verify cache time is recent
				if time.Since(geoData.CacheTime) > time.Minute {
					t.Errorf("Cache time seems too old for IP %s", tt.ip)
				}
				
				// For some IPs (like private IPs), country may be empty - that's OK
				t.Logf("IP %s: Country=%s, Region=%s", tt.ip, geoData.Country, geoData.Region)
			} else {
				if geoData != nil {
					t.Errorf("Expected nil geo data for IP %s, got %+v", tt.ip, geoData)
				}
			}
		})
	}
}

func testIPTunnelMappingOperations(t *testing.T) {
	// Clear existing mappings for clean test
	ipTunnelMappings = make(map[string]*IPTunnelMapping)
	
	testIP := "8.8.8.8"
	testTunnelID := "test-tunnel-123"
	
	// Test initial state - no mapping
	if mapping := getIPTunnelMapping(testIP); mapping != "" {
		t.Errorf("Expected empty mapping for new IP, got %s", mapping)
	}
	
	// Test recording IP tunnel mapping
	recordIPTunnelMapping(testIP, testTunnelID)
	
	// Test retrieval
	if mapping := getIPTunnelMapping(testIP); mapping != testTunnelID {
		t.Errorf("Expected tunnel ID %s, got %s", testTunnelID, mapping)
	}
	
	// Test mapping data structure
	ipTunnelMu.RLock()
	mappingData, exists := ipTunnelMappings[testIP]
	ipTunnelMu.RUnlock()
	
	if !exists {
		t.Fatal("Expected IP mapping to exist in internal storage")
	}
	
	if mappingData.IPAddress != testIP {
		t.Errorf("Expected IP %s, got %s", testIP, mappingData.IPAddress)
	}
	
	if mappingData.LastTunnelID != testTunnelID {
		t.Errorf("Expected tunnel ID %s, got %s", testTunnelID, mappingData.LastTunnelID)
	}
	
	if mappingData.UsageCount != 1 {
		t.Errorf("Expected usage count 1, got %d", mappingData.UsageCount)
	}
	
	if mappingData.SuccessRate != 1.0 {
		t.Errorf("Expected success rate 1.0, got %f", mappingData.SuccessRate)
	}
	
	// Test multiple recordings (should update success rate with EMA)
	recordIPTunnelMapping(testIP, testTunnelID)
	
	ipTunnelMu.RLock()
	updatedMapping := ipTunnelMappings[testIP]
	ipTunnelMu.RUnlock()
	
	if updatedMapping.UsageCount != 2 {
		t.Errorf("Expected usage count 2, got %d", updatedMapping.UsageCount)
	}
	
	// Test with different tunnel ID
	anotherTunnelID := "another-tunnel-456"
	recordIPTunnelMapping(testIP, anotherTunnelID)
	
	if mapping := getIPTunnelMapping(testIP); mapping != anotherTunnelID {
		t.Errorf("Expected updated tunnel ID %s, got %s", anotherTunnelID, mapping)
	}
}

func testGeoTunnelPreferences(t *testing.T) {
	// Clear existing preferences
	geoRouting = make(map[string]*GeoTunnelPreference)
	
	testIP := "8.8.8.8" // Should resolve to US
	testTunnelID := "us-tunnel-123"
	
	// Test initial state - no preference
	if pref := getGeoTunnelPreference(testIP); pref != "" {
		t.Errorf("Expected empty preference for new geo location, got %s", pref)
	}
	
	// Test recording geographical tunnel mapping
	recordGeoTunnelMapping(testIP, testTunnelID)
	
	// Test preference retrieval
	if pref := getGeoTunnelPreference(testIP); pref != testTunnelID {
		t.Errorf("Expected tunnel ID %s, got %s", testTunnelID, pref)
	}
	
	// Test geographical key generation
	geoData := lookupIPGeoData(testIP)
	if geoData != nil {
		expectedGeoKey := geoData.Country + "_" + geoData.Region
		
		geoRoutingMu.RLock()
		_, exists := geoRouting[expectedGeoKey]
		geoRoutingMu.RUnlock()
		
		if !exists {
			t.Errorf("Expected geographical preference to exist for key %s", expectedGeoKey)
		}
		
		t.Logf("Geographical routing created for key: %s", expectedGeoKey)
	}
	
	// Test multiple recordings for same geo location
	recordGeoTunnelMapping(testIP, testTunnelID)
	
	geoData = lookupIPGeoData(testIP)
	if geoData != nil {
		geoKey := geoData.Country + "_" + geoData.Region
		
		geoRoutingMu.RLock()
		pref, exists := geoRouting[geoKey]
		geoRoutingMu.RUnlock()
		
		if !exists {
			t.Fatal("Expected geographical preference to exist")
		}
		
		if pref.UsageCount < 2 {
			t.Errorf("Expected usage count >= 2, got %d", pref.UsageCount)
		}
		
		if pref.SuccessRate < 0.9 {
			t.Errorf("Expected high success rate, got %f", pref.SuccessRate)
		}
	}
}

func testGeoRoutingStats(t *testing.T) {
	// Set up some test data
	recordIPTunnelMapping("8.8.8.8", "us-tunnel-1")
	recordIPTunnelMapping("1.1.1.1", "us-tunnel-2")
	recordGeoTunnelMapping("8.8.8.8", "us-tunnel-1")
	recordGeoTunnelMapping("1.1.1.1", "us-tunnel-2")
	
	stats := getGeoRoutingStats()
	
	// Verify stats structure
	if stats == nil {
		t.Fatal("Expected geo routing stats, got nil")
	}
	
	// Check expected fields
	expectedFields := []string{"ip_mappings", "geo_preferences", "geoip_available"}
	for _, field := range expectedFields {
		if _, exists := stats[field]; !exists {
			t.Errorf("Expected field %s in geo routing stats", field)
		}
	}
	
	// Verify GeoIP availability
	if geoAvailable, ok := stats["geoip_available"].(bool); ok {
		if !geoAvailable {
			t.Error("Expected GeoIP to be available")
		}
	}
	
	// Verify non-zero mappings
	if ipMappings, ok := stats["ip_mappings"].(int); ok {
		if ipMappings == 0 {
			t.Error("Expected non-zero IP mappings")
		}
		t.Logf("IP mappings count: %d", ipMappings)
	}
	
	if geoPrefs, ok := stats["geo_preferences"].(int); ok {
		t.Logf("Geographical preferences count: %d", geoPrefs)
	}
	
	// Check for countries data if available
	if countries, ok := stats["countries"].(map[string]int); ok {
		if len(countries) == 0 {
			t.Log("No countries data available (this is normal for test data)")
		} else {
			t.Logf("Countries tracked: %v", countries)
		}
	}
}

func testGeoRoutingIntegration(t *testing.T) {
	// Test integration with client fingerprinting and smart routing
	
	// Create a mock request with various geographical indicators
	req := httptest.NewRequest("GET", "/assets/app.js", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("X-Forwarded-For", "8.8.8.8") // US IP
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.RemoteAddr = "8.8.8.8:1234"
	
	// Test client IP extraction
	clientIP := extractRealClientIP(req)
	if clientIP != "8.8.8.8" {
		t.Errorf("Expected client IP 8.8.8.8, got %s", clientIP)
	}
	
	// Test geographical data extraction
	geoData := lookupIPGeoData(clientIP)
	if geoData == nil {
		t.Error("Expected geo data for test IP")
		return
	}
	
	t.Logf("Extracted geo data - Country: %s, Region: %s", geoData.Country, geoData.Region)
	
	// Test fingerprint extraction includes geographical context
	fingerprint := extractFingerprint(req)
	if fingerprint == nil {
		t.Fatal("Expected client fingerprint")
	}
	
	if fingerprint.ClientIP != clientIP {
		t.Errorf("Expected client IP %s in fingerprint, got %s", clientIP, fingerprint.ClientIP)
	}
	
	// Test client tracking with geographical context
	clientKey := generateClientKey(req)
	if clientKey == "" {
		t.Fatal("Expected client key")
	}
	
	// Record some geographical mappings
	testTunnelID := "geo-test-tunnel-789"
	recordIPTunnelMapping(clientIP, testTunnelID)
	recordGeoTunnelMapping(clientIP, testTunnelID)
	
	// Test geographical tunnel preference
	preferredTunnel := getGeoTunnelPreference(clientIP)
	if preferredTunnel != testTunnelID {
		t.Errorf("Expected preferred tunnel %s, got %s", testTunnelID, preferredTunnel)
	}
	
	// Test IP-based tunnel mapping
	mappedTunnel := getIPTunnelMapping(clientIP)
	if mappedTunnel != testTunnelID {
		t.Errorf("Expected mapped tunnel %s, got %s", testTunnelID, mappedTunnel)
	}
	
	t.Logf("Geographical routing integration test completed successfully")
}

func TestGeoRoutingCleanup(t *testing.T) {
	// Test that old geographical data gets cleaned up appropriately
	
	// Create some test data with old timestamps
	testIP := "8.8.8.8"
	testTunnelID := "old-tunnel-999"
	
	// Record mapping
	recordIPTunnelMapping(testIP, testTunnelID)
	
	// Manually set old timestamp to test cleanup
	ipTunnelMu.Lock()
	if mapping, exists := ipTunnelMappings[testIP]; exists {
		mapping.LastSuccess = time.Now().Add(-25 * time.Hour) // 25 hours ago
	}
	ipTunnelMu.Unlock()
	
	// Test that old mapping is not returned
	result := getIPTunnelMapping(testIP)
	if result != "" {
		t.Errorf("Expected empty result for old mapping, got %s", result)
	}
	
	// Test with low success rate
	recordIPTunnelMapping(testIP, testTunnelID)
	
	ipTunnelMu.Lock()
	if mapping, exists := ipTunnelMappings[testIP]; exists {
		mapping.SuccessRate = 0.3 // Below threshold of 0.5
	}
	ipTunnelMu.Unlock()
	
	result = getIPTunnelMapping(testIP)
	if result != "" {
		t.Errorf("Expected empty result for low success rate mapping, got %s", result)
	}
}

func TestGeoRoutingEdgeCases(t *testing.T) {
	// Test edge cases and error conditions
	
	t.Run("EmptyInputs", func(t *testing.T) {
		// Test empty IP
		if result := lookupIPGeoData(""); result != nil {
			t.Errorf("Expected nil for empty IP, got %+v", result)
		}
		
		if result := getIPTunnelMapping(""); result != "" {
			t.Errorf("Expected empty result for empty IP, got %s", result)
		}
		
		if result := getGeoTunnelPreference(""); result != "" {
			t.Errorf("Expected empty result for empty IP, got %s", result)
		}
		
		// Test empty tunnel ID
		recordIPTunnelMapping("8.8.8.8", "")
		recordGeoTunnelMapping("8.8.8.8", "")
		// Should handle gracefully without panicking
	})
	
	t.Run("InvalidIPs", func(t *testing.T) {
		invalidIPs := []string{
			"invalid-ip",
			"999.999.999.999",
			"not.an.ip.address",
			"::invalid::ipv6::",
		}
		
		for _, ip := range invalidIPs {
			if result := lookupIPGeoData(ip); result != nil {
				t.Errorf("Expected nil for invalid IP %s, got %+v", ip, result)
			}
		}
	})
	
	t.Run("ConcurrentAccess", func(t *testing.T) {
		// Test concurrent access doesn't cause race conditions
		done := make(chan bool, 10)
		
		for i := 0; i < 10; i++ {
			go func(index int) {
				defer func() { done <- true }()
				
				testIP := "8.8.8.8"
				testTunnelID := fmt.Sprintf("concurrent-tunnel-%d", index)
				
				// Concurrent operations
				recordIPTunnelMapping(testIP, testTunnelID)
				getIPTunnelMapping(testIP)
				recordGeoTunnelMapping(testIP, testTunnelID)
				getGeoTunnelPreference(testIP)
				getGeoRoutingStats()
			}(i)
		}
		
		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
		
		// Verify no panics and data consistency
		if stats := getGeoRoutingStats(); stats == nil {
			t.Error("Expected geo routing stats after concurrent access")
		}
	})
}
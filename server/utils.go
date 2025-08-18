package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oschwald/geoip2-golang"
)

// Utility functions and helpers

// randHex generates a random hex string of the specified length
func randHex(n int) string {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", bytes)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
}

// isAssetRequest checks if a request is for a static asset
func isAssetRequest(path string) bool {
	// Common asset file extensions
	assetExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".json", ".xml",
		".txt", ".pdf", ".zip", ".tar.gz", ".mp4", ".mp3", ".wav",
		".webp", ".avif", ".webm", ".ogg", ".flv", ".swf",
	}

	// Common asset path prefixes
	assetPrefixes := []string{
		"/assets/", "/static/", "/public/", "/dist/", "/build/",
		"/js/", "/css/", "/images/", "/img/", "/fonts/", "/media/",
		"/_next/", "/_nuxt/", "/webpack/", "/vite/",
	}

	pathLower := strings.ToLower(path)

	// Check extensions
	for _, ext := range assetExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}

	// Check prefixes
	for _, prefix := range assetPrefixes {
		if strings.HasPrefix(pathLower, prefix) {
			return true
		}
	}

	return false
}

// isAPIRequest checks if a request is for an API endpoint
func isAPIRequest(path string) bool {
	apiPrefixes := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/", "/graphql",
		"/webhook/", "/callback/", "/auth/", "/oauth/", "/login/", "/logout/",
		"/health", "/status", "/ping", "/metrics", "/admin/",
	}

	pathLower := strings.ToLower(path)

	for _, prefix := range apiPrefixes {
		if strings.HasPrefix(pathLower, prefix) {
			return true
		}
	}

	return false
}

// Asset mapping and geographical routing support

var (
	// Client asset mapping (per-client tunnel preference)
	clientAssetMap = make(map[string]string) // clientKey -> tunnelID
	clientAssetMu  sync.RWMutex

	// IP-based geographical routing
	ipTunnelMappings = make(map[string]*IPTunnelMapping) // clientIP -> mapping
	ipTunnelMu       sync.RWMutex
	geoReader        *geoip2.Reader
	geoRouting       = make(map[string]*GeoTunnelPreference) // geoKey -> preference
	geoRoutingMu     sync.RWMutex
)

// recordClientAssetMapping records which tunnel a client should use for assets
func recordClientAssetMapping(clientKey, tunnelID string) {
	clientAssetMu.Lock()
	defer clientAssetMu.Unlock()
	clientAssetMap[clientKey] = tunnelID
}

// getClientAssetMapping retrieves the asset tunnel mapping for a client
func getClientAssetMapping(clientKey string) string {
	clientAssetMu.RLock()
	defer clientAssetMu.RUnlock()
	return clientAssetMap[clientKey]
}

// getClientAssetMappingWithFallback gets asset mapping with fallback strategies
func getClientAssetMappingWithFallback(r *http.Request, clientKey string) string {
	// Try direct mapping first
	if tunnelID := getClientAssetMapping(clientKey); tunnelID != "" {
		return tunnelID
	}

	// Try IP-based mapping
	clientIP := extractRealClientIP(r)
	if tunnelID := getIPTunnelMapping(clientIP); tunnelID != "" {
		return tunnelID
	}

	// Try referer-based detection
	if tunnelID := extractTunnelFromReferer(r); tunnelID != "" {
		return tunnelID
	}

	return ""
}

// IP-based geographical routing functions

// recordIPTunnelMapping records successful IP->tunnel mapping
func recordIPTunnelMapping(clientIP, tunnelID string) {
	if clientIP == "" || tunnelID == "" {
		return
	}

	ipTunnelMu.Lock()
	defer ipTunnelMu.Unlock()

	mapping, exists := ipTunnelMappings[clientIP]
	if !exists {
		mapping = &IPTunnelMapping{
			IPAddress:    clientIP,
			LastTunnelID: tunnelID,
			LastSuccess:  time.Now(),
			UsageCount:   1,
			SuccessRate:  1.0,
		}
		ipTunnelMappings[clientIP] = mapping
	} else {
		mapping.LastTunnelID = tunnelID
		mapping.LastSuccess = time.Now()
		mapping.UsageCount++

		// Update success rate using exponential moving average
		mapping.SuccessRate = mapping.SuccessRate*0.9 + 1.0*0.1
	}
}

// getIPTunnelMapping gets the preferred tunnel for an IP address
func getIPTunnelMapping(clientIP string) string {
	if clientIP == "" {
		return ""
	}

	ipTunnelMu.RLock()
	defer ipTunnelMu.RUnlock()

	mapping, exists := ipTunnelMappings[clientIP]
	if !exists {
		return ""
	}

	// Check if mapping is recent and has good success rate
	if time.Since(mapping.LastSuccess) > 24*time.Hour || mapping.SuccessRate < 0.5 {
		return ""
	}

	return mapping.LastTunnelID
}

// initGeoIP initializes GeoIP database if available
func initGeoIP() {
	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	if geoDBPath == "" {
		// Try common locations
		commonPaths := []string{
			"/usr/share/GeoIP/GeoLite2-City.mmdb",
			"/opt/geoip/GeoLite2-City.mmdb",
			"./GeoLite2-City.mmdb",
			"./geolite/GeoLite2-City.mmdb",
		}

		for _, path := range commonPaths {
			if _, err := os.Stat(path); err == nil {
				geoDBPath = path
				break
			}
		}
	}

	if geoDBPath != "" {
		if reader, err := geoip2.Open(geoDBPath); err == nil {
			geoReader = reader
			log.Printf("GeoIP database loaded from: %s", geoDBPath)
		} else {
			log.Printf("Failed to load GeoIP database from %s: %v", geoDBPath, err)
		}
	} else {
		log.Println("GeoIP database not found - geographical routing disabled")
	}
}

// lookupIPGeoData looks up geographical data for an IP address
func lookupIPGeoData(clientIP string) *IPGeoData {
	if geoReader == nil || clientIP == "" {
		return nil
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}

	record, err := geoReader.City(ip)
	if err != nil {
		return nil
	}

	subdivision := ""
	if len(record.Subdivisions) > 0 {
		subdivision = record.Subdivisions[0].Names["en"]
		if subdivision == "" {
			subdivision = record.Subdivisions[0].IsoCode
		}
	}

	city := record.City.Names["en"]

	return &IPGeoData{
		Country:   record.Country.Names["en"],
		Region:    subdivision,
		City:      city,
		CacheTime: time.Now(),
	}
}

// getGeoTunnelPreference gets preferred tunnel for a geographical location
func getGeoTunnelPreference(clientIP string) string {
	geoData := lookupIPGeoData(clientIP)
	if geoData == nil {
		return ""
	}

	geoKey := fmt.Sprintf("%s_%s", geoData.Country, geoData.Region)

	geoRoutingMu.RLock()
	defer geoRoutingMu.RUnlock()

	pref, exists := geoRouting[geoKey]
	if !exists || time.Since(pref.LastUsed) > 24*time.Hour || pref.SuccessRate < 0.5 {
		return ""
	}

	return pref.TunnelID
}

// recordGeoTunnelMapping records successful geographical routing
func recordGeoTunnelMapping(clientIP, tunnelID string) {
	geoData := lookupIPGeoData(clientIP)
	if geoData == nil || tunnelID == "" {
		return
	}

	geoKey := fmt.Sprintf("%s_%s", geoData.Country, geoData.Region)

	geoRoutingMu.Lock()
	defer geoRoutingMu.Unlock()

	pref, exists := geoRouting[geoKey]
	if !exists {
		pref = &GeoTunnelPreference{
			TunnelID:    tunnelID,
			UsageCount:  1,
			SuccessRate: 1.0,
			LastUsed:    time.Now(),
		}
		geoRouting[geoKey] = pref
	} else {
		pref.TunnelID = tunnelID
		pref.UsageCount++
		pref.SuccessRate = pref.SuccessRate*0.9 + 1.0*0.1
		pref.LastUsed = time.Now()
	}
}

// getGeoRoutingStats returns geographical routing statistics
func getGeoRoutingStats() map[string]interface{} {
	ipTunnelMu.RLock()
	geoRoutingMu.RLock()
	defer ipTunnelMu.RUnlock()
	defer geoRoutingMu.RUnlock()

	stats := map[string]interface{}{
		"ip_mappings":     len(ipTunnelMappings),
		"geo_preferences": len(geoRouting),
		"geoip_available": geoReader != nil,
	}

	// IP mapping statistics
	if len(ipTunnelMappings) > 0 {
		totalUsage := 0
		highSuccessRate := 0
		recentMappings := 0

		for _, mapping := range ipTunnelMappings {
			totalUsage += mapping.UsageCount
			if mapping.SuccessRate > 0.8 {
				highSuccessRate++
			}
			if time.Since(mapping.LastSuccess) < time.Hour {
				recentMappings++
			}
		}

		stats["ip_stats"] = map[string]interface{}{
			"total_usage":     totalUsage,
			"high_success":    highSuccessRate,
			"recent_mappings": recentMappings,
		}
	}

	// Geographical preferences
	if len(geoRouting) > 0 {
		countries := make(map[string]int)
		for geoKey := range geoRouting {
			parts := strings.Split(geoKey, "_")
			if len(parts) > 0 {
				countries[parts[0]]++
			}
		}
		stats["countries"] = countries
	}

	return stats
}

// detectCustomURLFromRedirect attempts to identify the custom URL that likely caused this redirect
func detectCustomURLFromRedirect(r *http.Request, clientKey string) string {
	// Check if this is a root path request that could be from a custom URL redirect
	if r.URL.Path != "/" && r.URL.Path != "" {
		return ""
	}

	// Look for referer that indicates a custom URL redirect
	referer := r.Header.Get("Referer")
	if referer != "" {
		// Extract the path from referer
		if refURL, err := url.Parse(referer); err == nil {
			refPath := strings.Trim(refURL.Path, "/")
			if refPath != "" {
				// Check if this referer path matches any custom URL
				customURLsMu.RLock()
				if tunnelID, exists := customURLs[refPath]; exists {
					customURLsMu.RUnlock()
					log.Printf("[CUSTOM URL DETECTION] Detected redirect from custom URL | Referer: %s | CustomURL: %s | TunnelID: %s | ClientKey: %s", referer, refPath, tunnelID, clientKey)
					return refPath
				}
				customURLsMu.RUnlock()
			}
		}
	}

	// Check if client has recent redirect sessions for any custom URL
	if activeSession := getActiveRedirectSession(clientKey); activeSession != nil {
		log.Printf("[CUSTOM URL DETECTION] Detected from active redirect session | CustomURL: %s | ClientKey: %s | RedirectTime: %v", activeSession.CustomURL, clientKey, activeSession.RedirectTime)
		return activeSession.CustomURL
	}

	return ""
}

// getCustomURLTunnel returns the tunnel ID for a given custom URL
func getCustomURLTunnel(customURL string) string {
	if customURL == "" {
		return ""
	}

	customURLsMu.RLock()
	tunnelID := customURLs[customURL]
	customURLsMu.RUnlock()

	return tunnelID
}

// smartFallbackHandler handles requests that don't match existing routes
func smartFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Skip if this is already a system endpoint (avoid infinite loops)
	if strings.HasPrefix(r.URL.Path, "/__pub__/") ||
		strings.HasPrefix(r.URL.Path, "/__ws__") ||
		strings.HasPrefix(r.URL.Path, "/__tcp__/") ||
		strings.HasPrefix(r.URL.Path, "/__health__") {
		http.NotFound(w, r)
		return
	}

	// Generate client key for enhanced tracking
	clientKey := generateClientKey(r)
	isAsset := isAssetRequest(r.URL.Path)
	isAPI := isAPIRequest(r.URL.Path)

	log.Printf("[SMART ROUTING] Request received | URL: %s | Method: %s | Asset: %v | API: %v | ClientKey: %s | RemoteAddr: %s", r.URL.Path, r.Method, isAsset, isAPI, clientKey, r.RemoteAddr)

	// Buffer request body early for multiple routing attempts (consultant fix for body consumption bug)
	bodyBytes, bodyReadErr := io.ReadAll(r.Body)
	if bodyReadErr != nil {
		log.Printf("[SMART ROUTING] Failed to read request body | URL: %s | Error: %v", r.URL.Path, bodyReadErr)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()
	log.Printf("[SMART ROUTING] Buffered request body | URL: %s | BodySize: %d", r.URL.Path, len(bodyBytes))

	// Declare tunnelIDs variable for reuse throughout function
	var tunnelIDs []string

	// PRIORITY: Custom URL redirect detection - handle requests that come from custom URL redirects
	if detectedCustomURL := detectCustomURLFromRedirect(r, clientKey); detectedCustomURL != "" {
		if tunnelID := getCustomURLTunnel(detectedCustomURL); tunnelID != "" {
			log.Printf("[SMART ROUTING] Custom URL redirect detected | URL: %s | CustomURL: %s | TunnelID: %s | ClientKey: %s", r.URL.Path, detectedCustomURL, tunnelID, clientKey)

			if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
				// Create or update redirect session for future requests
				createRedirectSession(clientKey, detectedCustomURL, tunnelID)
				clientTracker.RecordSuccess(clientKey, tunnelID)
				log.Printf("[SMART ROUTING] Custom URL redirect routing successful | URL: %s | CustomURL: %s | TunnelID: %s", r.URL.Path, detectedCustomURL, tunnelID)
				return
			} else {
				log.Printf("[SMART ROUTING] Custom URL redirect routing failed | URL: %s | CustomURL: %s | TunnelID: %s", r.URL.Path, detectedCustomURL, tunnelID)
			}
		}
	}

	// Check for active redirection sessions - route redirected clients to their assigned tunnels
	if redirectSession := getActiveRedirectSession(clientKey); redirectSession != nil {
		log.Printf("[SMART ROUTING] Found active redirect session | ClientKey: %s | URL: %s | TunnelID: %s | CustomURL: %s", clientKey, r.URL.Path, redirectSession.TunnelID, redirectSession.CustomURL)

		// Try the redirect session tunnel using buffered body
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, redirectSession.TunnelID, isAsset) {
			updateRedirectSession(redirectSession)
			log.Printf("[SMART ROUTING] Redirect session routing successful | ClientKey: %s | URL: %s | TunnelID: %s", clientKey, r.URL.Path, redirectSession.TunnelID)
			return
		}

		// CONSULTANT FIX: Conditional fallback logic based on tunnel count
		tunnelIDs = getActiveTunnelIDs()
		log.Printf("[SMART ROUTING] Redirect session failed | ClientKey: %s | TunnelID: %s | ActiveTunnels: %d | TunnelIDs: %v", clientKey, redirectSession.TunnelID, len(tunnelIDs), tunnelIDs)

		// Check if the tunnel is still connected
		ac := getAgent(redirectSession.TunnelID)
		if ac == nil {
			// Tunnel is completely disconnected - deactivate session
			log.Printf("[SMART ROUTING] Redirect session tunnel disconnected | ClientKey: %s | URL: %s | TunnelID: %s | Deactivating session", clientKey, r.URL.Path, redirectSession.TunnelID)
			redirectSession.Active = false
		} else {
			log.Printf("[SMART ROUTING] Redirect session tunnel still connected | ClientKey: %s | TunnelID: %s | Keeping session active", clientKey, redirectSession.TunnelID)
		}

		// CRITICAL: Conditional fallback logic to prevent misrouting
		if len(tunnelIDs) > 1 {
			// Multiple tunnels active - STOP processing to prevent misrouting to wrong tunnel
			log.Printf("[SMART ROUTING] STOPPING - Multiple tunnels active, preventing redirect session fallback | ActiveTunnels: %d | ClientKey: %s | SessionTunnel: %s", len(tunnelIDs), clientKey, redirectSession.TunnelID)
			http.Error(w, "tunnel routing failed", http.StatusBadGateway)
			return
		}

		// Single tunnel active - CONTINUE to fallback strategies (preserves single-tunnel resilience)
		log.Printf("[SMART ROUTING] CONTINUING - Single tunnel, allowing redirect session fallback | ActiveTunnels: %d | ClientKey: %s", len(tunnelIDs), clientKey)
	}

	// PRIORITY: Single tunnel optimization for ALL requests when only one tunnel exists
	tunnelIDs = getActiveTunnelIDs()
	log.Printf("[SMART ROUTING] Active tunnels check | Count: %d | TunnelIDs: %v", len(tunnelIDs), tunnelIDs)

	// If only one tunnel exists, route ALL requests to it (much simpler and more reliable)
	if len(tunnelIDs) == 1 {
		tunnelID := tunnelIDs[0]
		requestType := "regular"
		if isAPI {
			requestType = "api"
		} else if isAsset {
			requestType = "asset"
		}

		log.Printf("[SMART ROUTING] SINGLE TUNNEL optimization | Type: %s | URL: %s | TunnelID: %s | ClientKey: %s", requestType, r.URL.Path, tunnelID, clientKey)

		// Add extra logging for API requests to help debug 404 issues
		if isAPI {
			log.Printf("[SMART ROUTING] API REQUEST DETAILS | Method: %s | Path: %s | User-Agent: %s", r.Method, r.URL.Path, r.Header.Get("User-Agent"))
		}

		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
			// Learn this mapping for future requests
			clientTracker.LearnMapping(clientKey, tunnelID)
			clientTracker.RecordSuccess(clientKey, tunnelID)
			log.Printf("[SMART ROUTING] Single tunnel routing successful | URL: %s | TunnelID: %s | ClientKey: %s", r.URL.Path, tunnelID, clientKey)

			// Record client asset mappings
			if isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			} else if !isAPI {
				// Record asset mapping for regular pages
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (single-tunnel-%s-SUCCESS)", r.URL.Path, tunnelID, requestType)
			return
		} else {
			log.Printf("Smart routing: SINGLE TUNNEL routing failed for %s %s -> %s", requestType, r.URL.Path, tunnelID)
			// Don't return here - try other strategies below
		}
	} else {
		log.Printf("Smart routing: multiple tunnels detected (%d), using advanced routing", len(tunnelIDs))
	}

	// Asset cache removed - proceed directly to client asset mapping and other strategies

	// Enhanced Strategy: Check client asset mapping for asset requests
	if isAsset {
		if mappedTunnelID := getClientAssetMappingWithFallback(r, clientKey); mappedTunnelID != "" {
			if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, mappedTunnelID, isAsset) {
				clientTracker.RecordSuccess(clientKey, mappedTunnelID)
				log.Printf("Smart routing: %s -> tunnel %s (client-asset-mapping)", r.URL.Path, mappedTunnelID)
				return
			} else {
				log.Printf("Smart routing: client asset mapping failed for %s -> %s", r.URL.Path, mappedTunnelID)
			}
		}

		// If we reached here and only have one tunnel, something went wrong above
		// Let's try one more time with explicit handling
		tunnelIDs = getActiveTunnelIDs()
		if len(tunnelIDs) == 1 {
			tunnelID := tunnelIDs[0]
			log.Printf("Smart routing: RETRY - asset %s with single tunnel %s", r.URL.Path, tunnelID)
			if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
				// Record asset mapping for this client
				recordClientAssetMapping(clientKey, tunnelID)
				clientTracker.RecordSuccess(clientKey, tunnelID)

				log.Printf("Smart routing: %s -> tunnel %s (asset-retry-SUCCESS)", r.URL.Path, tunnelID)
				return
			} else {
				log.Printf("Smart routing: RETRY failed for asset %s -> %s", r.URL.Path, tunnelID)
			}
		}
	}

	// Strategy 1: Enhanced Client Tracking (EXISTING) - but skip if we have redirect sessions for this client
	// Check if client has any active redirect sessions first
	hasActiveRedirectSession := false
	clientTracker.mu.RLock()
	if session, exists := clientTracker.clientSessions[clientKey]; exists && session.RedirectSessions != nil {
		for _, redirectSession := range session.RedirectSessions {
			if redirectSession.Active && time.Since(redirectSession.RedirectTime) <= redirectSession.TTL {
				hasActiveRedirectSession = true
				break
			}
		}
	}
	clientTracker.mu.RUnlock()

	// Only use client tracker if no redirect sessions are active (prevents contamination)
	if !hasActiveRedirectSession {
		if tunnelID := clientTracker.GetBestTunnel(clientKey); tunnelID != "" {
			confidence := clientTracker.GetConfidence(clientKey, tunnelID)
			// Lower confidence threshold for API endpoints since they're critical
			minConfidence := 0.7
			if isAPIRequest(r.URL.Path) {
				minConfidence = 0.3 // Lower threshold for API calls
			}

			if confidence > minConfidence && tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
				clientTracker.RecordSuccess(clientKey, tunnelID)

				// Record geographical routing success (NEW)
				clientIP := extractRealClientIP(r)
				recordIPTunnelMapping(clientIP, tunnelID)

				// Record asset mapping for non-asset requests (main pages)
				if !isAsset {
					recordClientAssetMapping(clientKey, tunnelID)
				}

				log.Printf("Smart routing: %s -> tunnel %s (client-tracker, conf=%.2f)", r.URL.Path, tunnelID, confidence)
				return
			} else if confidence > minConfidence {
				// High confidence but failed - record failure
				clientTracker.RecordFailure(clientKey, tunnelID)
			}
		}
	} else {
		log.Printf("[SMART ROUTING] Skipping client tracker due to active redirect sessions | ClientKey: %s | URL: %s", clientKey, r.URL.Path)
	}

	// Strategy 1.4: Custom URL fallback - try all custom URLs with use_redirect that might match this client
	if r.URL.Path == "/" || r.URL.Path == "" {
		// This is a root request, possibly from a redirect - try to find matching custom URLs
		customURLsMu.RLock()
		var redirectCustomURLs []string
		for customURL, tunnelID := range customURLs {
			// Check if this custom URL has use_redirect enabled
			tunnelsMu.RLock()
			if tunnel, exists := tunnels[tunnelID]; exists && tunnel.UseRedirect {
				redirectCustomURLs = append(redirectCustomURLs, customURL)
			}
			tunnelsMu.RUnlock()
		}
		customURLsMu.RUnlock()

		if len(redirectCustomURLs) > 0 {
			log.Printf("[SMART ROUTING] Custom URL fallback | Found %d redirect-enabled custom URLs | ClientKey: %s | URLs: %v", len(redirectCustomURLs), clientKey, redirectCustomURLs)

			// Try each redirect-enabled custom URL to see if it works for this client
			for _, customURL := range redirectCustomURLs {
				if tunnelID := getCustomURLTunnel(customURL); tunnelID != "" {
					log.Printf("[SMART ROUTING] Trying custom URL fallback | CustomURL: %s | TunnelID: %s | ClientKey: %s", customURL, tunnelID, clientKey)

					if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
						// Success! Create redirect session for future requests
						createRedirectSession(clientKey, customURL, tunnelID)
						clientTracker.RecordSuccess(clientKey, tunnelID)
						log.Printf("[SMART ROUTING] Custom URL fallback successful | URL: %s | CustomURL: %s | TunnelID: %s", r.URL.Path, customURL, tunnelID)
						return
					} else {
						log.Printf("[SMART ROUTING] Custom URL fallback failed | CustomURL: %s | TunnelID: %s", customURL, tunnelID)
					}
				}
			}
		}
	}

	// Strategy 1.5: IP-based Geographical Routing (NEW)
	clientIP := extractRealClientIP(r)
	if tunnelID := getIPTunnelMapping(clientIP); tunnelID != "" {
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)
			recordIPTunnelMapping(clientIP, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (ip-mapping, ip=%s)", r.URL.Path, tunnelID, clientIP)
			return
		} else {
			log.Printf("Smart routing: IP mapping failed for %s -> %s (ip=%s)", r.URL.Path, tunnelID, clientIP)
		}
	}

	// Strategy 1.6: Geographical Region Routing (NEW)
	if tunnelID := getGeoTunnelPreference(clientIP); tunnelID != "" {
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)
			recordIPTunnelMapping(clientIP, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			geoData := lookupIPGeoData(clientIP)
			geoKey := ""
			if geoData != nil {
				geoKey = geoData.Country + "_" + geoData.Region
			}
			log.Printf("Smart routing: %s -> tunnel %s (geo-preference, ip=%s, geo=%s)", r.URL.Path, tunnelID, clientIP, geoKey)
			return
		} else {
			geoData := lookupIPGeoData(clientIP)
			geoKey := ""
			if geoData != nil {
				geoKey = geoData.Country + "_" + geoData.Region
			}
			log.Printf("Smart routing: Geo preference failed for %s -> %s (ip=%s, geo=%s)", r.URL.Path, tunnelID, clientIP, geoKey)
		}
	}

	// Strategy 2: Try Referer-based routing (Enhanced)
	if tunnelID := extractTunnelFromReferer(r); tunnelID != "" {
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
			// Learn this mapping for future requests
			clientTracker.LearnMapping(clientKey, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (referer)", r.URL.Path, tunnelID)
			return
		}
	}

	// Strategy 3: Try all active tunnels in parallel (enhanced with learning)
	if len(tunnelIDs) == 0 {
		http.NotFound(w, r)
		return
	}

	// Body was already read and buffered at the beginning of the function

	// Use channels to handle parallel attempts
	type tunnelResult struct {
		tunnelID string
		success  bool
	}

	resultCh := make(chan tunnelResult, len(tunnelIDs))

	// Try each tunnel in parallel with appropriate timeout
	for _, tunnelID := range tunnelIDs {
		go func(tid string) {
			// Create a new request with the same body for each attempt
			newReq := r.Clone(r.Context())
			newReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

			success := tryTunnelRouteWithTimeout(&discardResponseWriter{}, newReq, tid, isAsset)
			resultCh <- tunnelResult{tunnelID: tid, success: success}
		}(tunnelID)
	}

	// Collect all results to learn from failures too
	var successfulTunnelID string
	var results []tunnelResult

	for range len(tunnelIDs) {
		result := <-resultCh
		results = append(results, result)
		if result.success && successfulTunnelID == "" {
			successfulTunnelID = result.tunnelID
		}
	}

	// Learn from all results - but avoid contamination if client has active redirect sessions
	clientTracker.mu.RLock()
	hasActiveRedirectSessionForLearning := false
	if session, exists := clientTracker.clientSessions[clientKey]; exists && session.RedirectSessions != nil {
		for _, redirectSession := range session.RedirectSessions {
			if redirectSession.Active && time.Since(redirectSession.RedirectTime) <= redirectSession.TTL {
				hasActiveRedirectSessionForLearning = true
				break
			}
		}
	}
	clientTracker.mu.RUnlock()

	for _, result := range results {
		if result.success {
			// Only learn mapping if no active redirect sessions (prevents contamination)
			if !hasActiveRedirectSessionForLearning {
				clientTracker.LearnMapping(clientKey, result.tunnelID)
				// Record geographical mapping for successful results (NEW)
				recordIPTunnelMapping(clientIP, result.tunnelID)
				log.Printf("[SMART ROUTING] Learning new mapping | ClientKey: %s | TunnelID: %s | URL: %s", clientKey, result.tunnelID, r.URL.Path)
			} else {
				log.Printf("[SMART ROUTING] Skipping mapping learning due to active redirect sessions | ClientKey: %s | TunnelID: %s | URL: %s", clientKey, result.tunnelID, r.URL.Path)
			}
		} else {
			clientTracker.RecordFailure(clientKey, result.tunnelID)
		}
	}

	// If we found a working tunnel, make the real request
	if successfulTunnelID != "" {
		// Create final request with original body
		finalReq := r.Clone(r.Context())
		finalReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		if tryTunnelRouteWithTimeout(w, finalReq, successfulTunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, successfulTunnelID)

			// Record geographical mapping (NEW)
			recordIPTunnelMapping(clientIP, successfulTunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, successfulTunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (parallel)", r.URL.Path, successfulTunnelID)
			return
		}
	}

	// ULTIMATE FALLBACK: Single tunnel catch-all for any missed requests
	if len(tunnelIDs) == 1 {
		tunnelID := tunnelIDs[0]
		log.Printf("Smart routing: ULTIMATE FALLBACK - trying single tunnel %s for %s", tunnelID, r.URL.Path)

		// Create final request with original body
		finalReq := r.Clone(r.Context())
		finalReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		// Use extended timeout for ultimate fallback to give agent more time
		extendedTimeout := 30 * time.Second
		if isAsset {
			extendedTimeout = 45 * time.Second
		}

		ctx, cancel := context.WithTimeout(r.Context(), extendedTimeout)
		defer cancel()

		// Try with extended timeout for final attempt
		ac := getAgent(tunnelID)
		if ac != nil {
			reqID := uuid.NewString()
			req := &ReqFrame{
				Type:    "req",
				ReqID:   reqID,
				Method:  finalReq.Method,
				Path:    finalReq.URL.Path,
				Query:   finalReq.URL.RawQuery,
				Headers: finalReq.Header,
				Body:    bodyBytes,
			}

			respCh := make(chan *RespFrame, 1)
			ac.registerWaiter(reqID, respCh)

			if err := ac.writeEncrypted(ctx, req); err == nil {
				select {
				case resp := <-respCh:
					clientTracker.RecordSuccess(clientKey, tunnelID)

					// Record geographical mapping (NEW)
					recordIPTunnelMapping(clientIP, tunnelID)

					// Record client asset mappings
					if isAsset {
						recordClientAssetMapping(clientKey, tunnelID)
					} else if !isAPI {
						recordClientAssetMapping(clientKey, tunnelID)
					}

					// Write response
					for k, vs := range resp.Headers {
						for _, v := range vs {
							w.Header().Add(k, v)
						}
					}
					if resp.Status == 0 {
						resp.Status = http.StatusOK
					}
					w.WriteHeader(resp.Status)
					_, _ = w.Write(resp.Body)

					log.Printf("Smart routing: %s -> tunnel %s (ultimate-fallback-EXTENDED-SUCCESS)", r.URL.Path, tunnelID)
					return
				case <-ctx.Done():
					log.Printf("Smart routing: ultimate fallback timeout for %s -> %s", r.URL.Path, tunnelID)
				}
			} else {
				log.Printf("Smart routing: ultimate fallback write error for %s -> %s: %v", r.URL.Path, tunnelID, err)
			}
		} else {
			log.Printf("Smart routing: ultimate fallback - agent %s not found", tunnelID)
		}
	}

	// No tunnel worked
	log.Printf("Smart routing failed: %s (tried %d tunnels, isAPI: %v, isAsset: %v)", r.URL.Path, len(tunnelIDs), isAPI, isAsset)
	http.NotFound(w, r)
}

// discardResponseWriter methods
func (d *discardResponseWriter) Header() http.Header {
	if d.headers == nil {
		d.headers = make(map[string][]string)
	}
	return d.headers
}

func (d *discardResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (d *discardResponseWriter) WriteHeader(status int) {
	d.status = status
}

// Initialize GeoIP on module load
func init() {
	// Try to find GeoIP database in server directory or subdirectories
	if _, err := os.Stat("server"); err == nil {
		// We're probably in the root directory, check server subdirectory
		if files, err := filepath.Glob("server/geolite/*.mmdb"); err == nil && len(files) > 0 {
			os.Setenv("GEOIP_DB_PATH", files[0])
		}
	} else {
		// We're probably in the server directory already
		if files, err := filepath.Glob("geolite/*.mmdb"); err == nil && len(files) > 0 {
			os.Setenv("GEOIP_DB_PATH", files[0])
		}
	}

	initGeoIP()
}

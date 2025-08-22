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
	// PRIORITY 1: Check if client has active redirect sessions for any custom URL
	// This should work for ALL paths, not just root paths
	if activeSession := getActiveRedirectSession(clientKey); activeSession != nil {
		log.Printf("[REDIRECT SESSION DETECTION] Found active session | CustomURL: %s | TunnelID: %s | ClientKey: %s | Path: %s | RedirectTime: %v",
			activeSession.CustomURL, activeSession.TunnelID, clientKey, r.URL.Path, activeSession.RedirectTime)
		return activeSession.CustomURL
	}

	// PRIORITY 2: For root path requests, also check referer-based detection
	if r.URL.Path == "/" || r.URL.Path == "" {
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
						log.Printf("[REFERER DETECTION] Detected redirect from custom URL | Referer: %s | CustomURL: %s | TunnelID: %s | ClientKey: %s", referer, refPath, tunnelID, clientKey)
						return refPath
					}
					customURLsMu.RUnlock()
				}
			}
		}
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

// getTunnelCustomURL returns the custom URL for a given tunnel ID
func getTunnelCustomURL(tunnelID string) string {
	if tunnelID == "" {
		return ""
	}

	// First check tunnel info for custom URL
	tunnelsMu.RLock()
	tunnel := tunnels[tunnelID]
	tunnelsMu.RUnlock()

	if tunnel != nil && tunnel.CustomURL != "" {
		return tunnel.CustomURL
	}

	// Fallback: search through custom URL mappings
	customURLsMu.RLock()
	defer customURLsMu.RUnlock()

	for customURL, mappedTunnelID := range customURLs {
		if mappedTunnelID == tunnelID {
			return customURL
		}
	}

	return ""
}

// smartFallbackHandler handles requests that don't match existing routes
func smartFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// System endpoints are already filtered by customURLHandler before calling this function

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

	// PRIORITY: Check for custom URL affinity - route clients to their established tunnel
	if affinity := affinityManager.GetValidatedAffinity(clientKey); affinity != nil {
		log.Printf("[AFFINITY] Using custom URL affinity | ClientKey: %s | TunnelID: %s | CustomURL: %s | Source: %s | AccessCount: %d",
			clientKey, affinity.TunnelID, affinity.CustomURL, affinity.Source, affinity.AccessCount)

		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, affinity.TunnelID, isAsset) {
			affinityManager.UpdateAccess(clientKey) // Update last access time and count
			log.Printf("[AFFINITY] Affinity routing successful | URL: %s | TunnelID: %s | CustomURL: %s", r.URL.Path, affinity.TunnelID, affinity.CustomURL)
			return
		} else {
			// Tunnel failed - check if tunnel still exists before clearing affinity
			tunnelIDs = getActiveTunnelIDs()
			tunnelExists := false
			for _, id := range tunnelIDs {
				if id == affinity.TunnelID {
					tunnelExists = true
					break
				}
			}

			if !tunnelExists {
				// Tunnel disconnected - clear affinity
				affinityManager.ClearAffinity(clientKey)
				log.Printf("[AFFINITY] Tunnel disconnected, cleared affinity | ClientKey: %s | TunnelID: %s", clientKey, affinity.TunnelID)
			} else {
				// Tunnel exists but failed - keep affinity for retry, but continue to fallbacks
				log.Printf("[AFFINITY] Tunnel failed temporarily, keeping affinity | ClientKey: %s | TunnelID: %s", clientKey, affinity.TunnelID)
			}
		}
	}

	// PRIORITY 1: Check for ANY redirect session associated with this IP (ultra-protective)
	clientIP := extractRealClientIP(r)
	clientTracker.mu.RLock()
	if ipClients, exists := clientTracker.ipMappings[clientIP]; exists {
		for _, ipClientKey := range ipClients {
			if session, exists := clientTracker.clientSessions[ipClientKey]; exists && session.RedirectSessions != nil {
				for _, redirectSession := range session.RedirectSessions {
					if redirectSession.Active && time.Since(redirectSession.RedirectTime) <= redirectSession.TTL {
						clientTracker.mu.RUnlock()
						log.Printf("[IP REDIRECT PROTECTION] Found active redirect session for IP | IP: %s | OriginalClientKey: %s | CurrentClientKey: %s | CustomURL: %s | TunnelID: %s",
							clientIP, ipClientKey, clientKey, redirectSession.CustomURL, redirectSession.TunnelID)

						if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, redirectSession.TunnelID, isAsset) {
							// Create redirect session for current client key too
							createRedirectSession(clientKey, redirectSession.CustomURL, redirectSession.TunnelID)
							updateRedirectSession(redirectSession)
							log.Printf("[IP REDIRECT PROTECTION] Routing successful | IP: %s | URL: %s | TunnelID: %s", clientIP, r.URL.Path, redirectSession.TunnelID)
							return
						}
						goto continueRouting
					}
				}
			}
		}
	}
	clientTracker.mu.RUnlock()

continueRouting:

	// PRIORITY 2: Custom URL redirect detection - handle requests that come from custom URL redirects
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

		// Try the redirect session tunnel
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, redirectSession.TunnelID, isAsset) {
			updateRedirectSession(redirectSession)
			log.Printf("[SMART ROUTING] Redirect session routing successful | ClientKey: %s | URL: %s | TunnelID: %s", clientKey, r.URL.Path, redirectSession.TunnelID)
			return
		}

		// If we reach here, there was an actual connection failure (timeout, agent disconnected)
		// Deactivate the redirect session and continue to fallback routing
		log.Printf("[SMART ROUTING] Redirect session connection failed | ClientKey: %s | TunnelID: %s | Deactivating session", clientKey, redirectSession.TunnelID)
		redirectSession.Active = false

		// Check tunnel count for conditional fallback logic
		tunnelIDs = getActiveTunnelIDs()
		log.Printf("[SMART ROUTING] Redirect tunnel failed, checking fallback options | ActiveTunnels: %d | TunnelIDs: %v", len(tunnelIDs), tunnelIDs)

		// CONSULTANT FIX: Prevent misrouting when multiple tunnels are active
		if len(tunnelIDs) > 1 {
			// Multiple tunnels active - STOP processing to prevent misrouting to wrong tunnel
			log.Printf("[SMART ROUTING] STOPPING - Multiple tunnels active, preventing redirect session fallback | ActiveTunnels: %d | ClientKey: %s | SessionTunnel: %s", len(tunnelIDs), clientKey, redirectSession.TunnelID)
			http.Error(w, "tunnel routing failed", http.StatusBadGateway)
			return
		}

		// Single tunnel active - CONTINUE to fallback strategies (preserves single-tunnel resilience)
		log.Printf("[SMART ROUTING] CONTINUING - Single tunnel, allowing redirect session fallback | ActiveTunnels: %d | ClientKey: %s", len(tunnelIDs), clientKey)
	}

	// Initialize tunnelIDs for later routing strategies
	tunnelIDs = getActiveTunnelIDs()
	log.Printf("[SMART ROUTING] Active tunnels available | Count: %d | TunnelIDs: %v", len(tunnelIDs), tunnelIDs)

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

		// Asset retry logic has been removed - let parallel attempts handle asset routing consistently
	}

	// Strategy 1: Enhanced Client Tracking - only reached if no active redirect sessions
	// (redirect sessions are handled earlier in the function)
	{
		if tunnelID := clientTracker.GetBestTunnel(clientKey); tunnelID != "" {
			confidence := clientTracker.GetConfidence(clientKey, tunnelID)
			// Lower confidence threshold for API endpoints since they're critical
			minConfidence := 0.7
			if isAPIRequest(r.URL.Path) {
				minConfidence = 0.3 // Lower threshold for API calls
			}

			if confidence > minConfidence && tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
				clientTracker.RecordSuccess(clientKey, tunnelID)

				// CRITICAL: Set smart routing affinity for successful requests
				customURL := getTunnelCustomURL(tunnelID)
				affinityManager.SetAffinity(clientKey, tunnelID, customURL, "client_tracker_route")

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
	}

	// NOTE: Custom URL fallback strategy removed - now handled by enhanced redirect session detection
	// The detectCustomURLFromRedirect() function properly handles all cases that this strategy covered

	// Strategy 1.5: IP-based Geographical Routing (NEW)
	// clientIP already extracted above for IP redirect protection
	if tunnelID := getIPTunnelMapping(clientIP); tunnelID != "" {
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)
			recordIPTunnelMapping(clientIP, tunnelID)

			// CRITICAL: Set smart routing affinity for successful requests
			customURL := getTunnelCustomURL(tunnelID)
			affinityManager.SetAffinity(clientKey, tunnelID, customURL, "ip_mapping_route")

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

	// Strategy 3: Conservative parallel routing - only for specific scenarios
	if len(tunnelIDs) == 0 {
		http.NotFound(w, r)
		return
	}

	// RESTRICTION 1: Never use parallel routing for API requests in multi-tenant environments
	// API endpoints often overlap between services, causing cross-contamination
	if isAPI && len(tunnelIDs) > 1 {
		log.Printf("[PARALLEL ROUTING] BLOCKED - API request with multiple tunnels, preventing cross-contamination | URL: %s | TunnelCount: %d", r.URL.Path, len(tunnelIDs))
		http.Error(w, "API routing blocked to prevent cross-contamination", http.StatusBadGateway)
		return
	}

	// RESTRICTION 2: Never use parallel routing when ANY IP from same network has redirect sessions
	// This prevents contamination even with fingerprinting variations
	// (IP redirect protection already checked above - this adds additional logging)

	// RESTRICTION 3: Only use parallel routing for truly unknown scenarios
	// Check if this is a completely new client with no prior interaction
	clientTracker.mu.RLock()
	hasAnyPriorInteraction := false
	if _, exists := clientTracker.clientSessions[clientKey]; exists {
		hasAnyPriorInteraction = true
	}
	// Also check if this IP has any prior mappings
	if ipClients, exists := clientTracker.ipMappings[clientIP]; exists && len(ipClients) > 0 {
		hasAnyPriorInteraction = true
	}
	clientTracker.mu.RUnlock()

	if hasAnyPriorInteraction && len(tunnelIDs) > 1 {
		log.Printf("[PARALLEL ROUTING] BLOCKED - Prior interaction detected with multiple tunnels, using first tunnel only | URL: %s | ClientKey: %s", r.URL.Path, clientKey)
		// Use first tunnel instead of parallel attempts
		tunnelIDs = []string{tunnelIDs[0]}
	}

	// OPTION: Completely disable parallel routing via environment variable
	if os.Getenv("DISABLE_PARALLEL_ROUTING") == "true" {
		log.Printf("[PARALLEL ROUTING] DISABLED - Environment variable set, using first tunnel only | URL: %s | TunnelID: %s", r.URL.Path, tunnelIDs[0])
		if tryTunnelRouteWithBufferedBody(w, r, bodyBytes, tunnelIDs[0], isAsset) {
			log.Printf("Smart routing: %s -> tunnel %s (first-tunnel-only)", r.URL.Path, tunnelIDs[0])
			return
		} else {
			http.Error(w, "tunnel routing failed", http.StatusBadGateway)
			return
		}
	}

	log.Printf("[PARALLEL ROUTING] Proceeding with conservative approach | URL: %s | TunnelCount: %d | IsAPI: %v | PriorInteraction: %v",
		r.URL.Path, len(tunnelIDs), isAPI, hasAnyPriorInteraction)

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

			success := tryTunnelRouteWithBufferedBody(&discardResponseWriter{}, newReq, bodyBytes, tid, isAsset)
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

		if tryTunnelRouteWithBufferedBody(w, finalReq, bodyBytes, successfulTunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, successfulTunnelID)

			// CRITICAL: Set smart routing affinity for successful requests
			customURL := getTunnelCustomURL(successfulTunnelID)
			affinityManager.SetAffinity(clientKey, successfulTunnelID, customURL, "parallel_route")

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

	// ULTIMATE FALLBACK: Try each tunnel with extended timeout for any missed requests
	if len(tunnelIDs) > 0 {
		tunnelID := tunnelIDs[0]
		log.Printf("[ROUTING PATH] ULTIMATE FALLBACK entered for %s -> tunnel %s | ContentType: %s | UserAgent: %s", r.URL.Path, tunnelID, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"))

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

					// CRITICAL: Set smart routing affinity for successful requests
					customURL := getTunnelCustomURL(tunnelID)
					affinityManager.SetAffinity(clientKey, tunnelID, customURL, "ultimate_fallback_route")

					// Record geographical mapping (NEW)
					recordIPTunnelMapping(clientIP, tunnelID)

					// Record client asset mappings
					if isAsset {
						recordClientAssetMapping(clientKey, tunnelID)
					} else if !isAPI {
						recordClientAssetMapping(clientKey, tunnelID)
					}

					// DIAGNOSTIC: Log headers received from agent in ultimate fallback
					log.Printf("[ULTIMATE FALLBACK] Headers from agent | TunnelID: %s | Path: %s | Headers: %+v", tunnelID, r.URL.Path, resp.Headers)

					// DIAGNOSTIC: Check content-type specifically in ultimate fallback
					if contentType, exists := resp.Headers["Content-Type"]; exists {
						log.Printf("[ULTIMATE FALLBACK] Content-Type from agent | TunnelID: %s | Path: %s | ContentType: %v", tunnelID, r.URL.Path, contentType)
					}

					// Write response
					for k, vs := range resp.Headers {
						for _, v := range vs {
							w.Header().Add(k, v)
						}
					}

					// CRITICAL FIX: Ensure Content-Type is explicitly set to prevent Go's auto-detection
					// This is the MISSING Content-Type protection that was causing the issue!
					if contentTypeHeaders := w.Header().Values("Content-Type"); len(contentTypeHeaders) == 0 {
						// No Content-Type header found, set default for streaming
						w.Header().Set("Content-Type", "text/event-stream")
						log.Printf("[ULTIMATE FALLBACK] CONTENT-TYPE FIX - No Content-Type found, setting default | TunnelID: %s | Path: %s", tunnelID, r.URL.Path)
					} else {
						// Content-Type exists, ensure it's properly set (not just added)
						existingContentType := contentTypeHeaders[0]
						w.Header().Set("Content-Type", existingContentType)
						log.Printf("[ULTIMATE FALLBACK] CONTENT-TYPE FIX - Reinforcing existing Content-Type | TunnelID: %s | Path: %s | ContentType: %s", tunnelID, r.URL.Path, existingContentType)
					}

					// DIAGNOSTIC: Log headers after Content-Type protection
					log.Printf("[ULTIMATE FALLBACK] Headers set on response writer (after Content-Type fix) | TunnelID: %s | Path: %s | Headers: %+v", tunnelID, r.URL.Path, w.Header())

					if resp.Status == 0 {
						resp.Status = http.StatusOK
					}
					w.WriteHeader(resp.Status)

					// DIAGNOSTIC: Log final response headers after WriteHeader  
					log.Printf("[ULTIMATE FALLBACK] Final response headers sent to client | TunnelID: %s | Path: %s | Status: %d | Headers: %+v", tunnelID, r.URL.Path, resp.Status, w.Header())

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

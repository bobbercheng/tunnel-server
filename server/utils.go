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
	// Asset mapping cache
	assetCache      = make(map[string]string) // path -> tunnelID
	assetCacheMu    sync.RWMutex
	clientAssetMap  = make(map[string]string) // clientKey -> tunnelID
	clientAssetMu   sync.RWMutex

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
		subdivision = record.Subdivisions[0].IsoCode
	}
	return &IPGeoData{
		Country:   record.Country.IsoCode,
		Region:    subdivision,
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
		"ip_mappings":       len(ipTunnelMappings),
		"geo_preferences":   len(geoRouting),
		"geoip_available":   geoReader != nil,
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
			"total_usage":      totalUsage,
			"high_success":     highSuccessRate,
			"recent_mappings":  recentMappings,
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

// smartFallbackHandler handles requests that don't match existing routes
func smartFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Skip if this is already a system endpoint (avoid infinite loops)
	if strings.HasPrefix(r.URL.Path, "/__pub__/") ||
		strings.HasPrefix(r.URL.Path, "/__register__") ||
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

	log.Printf("Smart routing: handling request %s (asset: %v, api: %v, client: %s)", r.URL.Path, isAsset, isAPI, clientKey)

	// PRIORITY: Single tunnel optimization for ALL requests when only one tunnel exists
	tunnelIDs := getActiveTunnelIDs()
	log.Printf("Smart routing: active tunnels count: %d", len(tunnelIDs))

	// If only one tunnel exists, route ALL requests to it (much simpler and more reliable)
	if len(tunnelIDs) == 1 {
		tunnelID := tunnelIDs[0]
		requestType := "regular"
		if isAPI {
			requestType = "api"
		} else if isAsset {
			requestType = "asset"
		}

		log.Printf("Smart routing: SINGLE TUNNEL - routing %s request %s to tunnel %s", requestType, r.URL.Path, tunnelID)

		// Add extra logging for API requests to help debug 404 issues
		if isAPI {
			log.Printf("Smart routing: API REQUEST DETAILS - Method: %s, Path: %s, Headers: %v", r.Method, r.URL.Path, r.Header)
		}

		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			// Learn this mapping for future requests
			clientTracker.LearnMapping(clientKey, tunnelID)
			clientTracker.RecordSuccess(clientKey, tunnelID)

			// Cache assets and record mappings
			if isAsset {
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = tunnelID
				assetCacheMu.Unlock()
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

	// Check asset cache first
	assetCacheMu.RLock()
	if cachedTunnelID, exists := assetCache[r.URL.Path]; exists {
		assetCacheMu.RUnlock()
		if tryTunnelRouteWithTimeout(w, r, cachedTunnelID, isAsset) {
			// Record success in client tracker
			clientTracker.RecordSuccess(clientKey, cachedTunnelID)
			log.Printf("Smart routing: %s -> tunnel %s (cached)", r.URL.Path, cachedTunnelID)
			return
		}
		// Remove invalid cache entry
		assetCacheMu.Lock()
		delete(assetCache, r.URL.Path)
		assetCacheMu.Unlock()
	} else {
		assetCacheMu.RUnlock()
	}

	// Enhanced Strategy: Check client asset mapping for asset requests
	if isAsset {
		if mappedTunnelID := getClientAssetMappingWithFallback(r, clientKey); mappedTunnelID != "" {
			if tryTunnelRouteWithTimeout(w, r, mappedTunnelID, isAsset) {
				// Cache successful mapping
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = mappedTunnelID
				assetCacheMu.Unlock()

				clientTracker.RecordSuccess(clientKey, mappedTunnelID)
				log.Printf("Smart routing: %s -> tunnel %s (client-asset-mapping)", r.URL.Path, mappedTunnelID)
				return
			} else {
				log.Printf("Smart routing: client asset mapping failed for %s -> %s", r.URL.Path, mappedTunnelID)
			}
		}

		// If we reached here and only have one tunnel, something went wrong above
		// Let's try one more time with explicit handling
		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) == 1 {
			tunnelID := tunnelIDs[0]
			log.Printf("Smart routing: RETRY - asset %s with single tunnel %s", r.URL.Path, tunnelID)
			if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
				// Cache successful mapping
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = tunnelID
				assetCacheMu.Unlock()

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

	// Strategy 1: Enhanced Client Tracking (EXISTING)
	if tunnelID := clientTracker.GetBestTunnel(clientKey); tunnelID != "" {
		confidence := clientTracker.GetConfidence(clientKey, tunnelID)
		// Lower confidence threshold for API endpoints since they're critical
		minConfidence := 0.7
		if isAPIRequest(r.URL.Path) {
			minConfidence = 0.3 // Lower threshold for API calls
		}

		if confidence > minConfidence && tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
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

	// Strategy 1.5: IP-based Geographical Routing (NEW)
	clientIP := extractRealClientIP(r)
	if tunnelID := getIPTunnelMapping(clientIP); tunnelID != "" {
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
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
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
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
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
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

	// Read request body once for reuse
	bodyBytes, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

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

	// Learn from all results
	for _, result := range results {
		if result.success {
			clientTracker.LearnMapping(clientKey, result.tunnelID)
			// Record geographical mapping for successful results (NEW)
			recordIPTunnelMapping(clientIP, result.tunnelID)
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

					// Cache assets and record mappings
					if isAsset {
						assetCacheMu.Lock()
						assetCache[r.URL.Path] = tunnelID
						assetCacheMu.Unlock()
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
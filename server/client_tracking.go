package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Client tracking and smart routing functionality

// NewClientTracker creates a new client tracker with default settings
func NewClientTracker() *ClientTracker {
	return &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      24 * time.Hour,
		cleanupInterval: 1 * time.Hour,
	}
}

// generateClientKey creates a unique key for client tracking
func generateClientKey(r *http.Request) string {
	fingerprint := extractFingerprint(r)
	return fingerprint.FingerprintHash
}

// extractFingerprint generates a client fingerprint from the request
func extractFingerprint(r *http.Request) *ClientFingerprint {
	fp := &ClientFingerprint{
		CreatedAt: time.Now(),
	}

	// Core identification
	fp.ClientIP = extractRealClientIP(r)
	fp.UserAgent = r.Header.Get("User-Agent")

	// Session and authentication
	fp.SessionCookie = extractSessionCookie(r)
	fp.Authorization = hashString(r.Header.Get("Authorization"))

	// Auth cookies
	fp.AuthCookies = make(map[string]string)
	for _, cookie := range r.Cookies() {
		if isAuthCookie(cookie.Name) {
			fp.AuthCookies[cookie.Name] = hashString(cookie.Value)
		}
	}

	// Session tokens from custom headers
	fp.SessionTokens = make(map[string]string)
	sessionHeaders := []string{"X-Auth-Token", "X-Session-ID", "X-CSRF-Token", "X-API-Key"}
	for _, header := range sessionHeaders {
		if value := r.Header.Get(header); value != "" {
			fp.SessionTokens[header] = hashString(value)
		}
	}

	// Browser fingerprinting
	fp.AcceptLanguage = r.Header.Get("Accept-Language")
	fp.AcceptEncoding = r.Header.Get("Accept-Encoding")
	fp.AcceptCharset = r.Header.Get("Accept-Charset")
	fp.DNT = r.Header.Get("DNT")

	// Network headers
	fp.XForwardedFor = r.Header.Get("X-Forwarded-For")
	fp.XRealIP = r.Header.Get("X-Real-IP")
	fp.XClientIP = r.Header.Get("X-Client-IP")
	fp.CFConnectingIP = r.Header.Get("CF-Connecting-IP")
	fp.XOriginalHost = r.Header.Get("X-Original-Host")

	// Application context
	fp.Origin = r.Header.Get("Origin")
	fp.Referer = r.Header.Get("Referer")
	fp.Host = r.Host

	// Browser capabilities
	fp.Connection = r.Header.Get("Connection")
	fp.CacheControl = r.Header.Get("Cache-Control")
	fp.Pragma = r.Header.Get("Pragma")

	// Custom headers for additional fingerprinting
	fp.CustomHeaders = make(map[string]string)
	customHeaderPrefixes := []string{"X-", "CF-", "CloudFront-"}
	for name, values := range r.Header {
		for _, prefix := range customHeaderPrefixes {
			if strings.HasPrefix(name, prefix) && len(values) > 0 {
				fp.CustomHeaders[name] = values[0]
				break
			}
		}
	}

	// Generate fingerprint hash
	fp.FingerprintHash = generateFingerprintHash(fp)
	fp.Confidence = calculateFingerprintConfidence(fp)

	return fp
}

// extractRealClientIP extracts the real client IP from various headers
func extractRealClientIP(r *http.Request) string {
	// Priority order for IP extraction
	headers := []string{
		"CF-Connecting-IP", // Cloudflare
		"X-Real-IP",
		"X-Forwarded-For",
		"X-Client-IP",
		"X-Forwarded",
		"X-Cluster-Client-IP",
		"Forwarded-For",
		"Forwarded",
	}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" {
			// For X-Forwarded-For, take the first IP (original client)
			if header == "X-Forwarded-For" && strings.Contains(ip, ",") {
				ip = strings.TrimSpace(strings.Split(ip, ",")[0])
			}
			
			// Validate IP
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// extractSessionCookie extracts session-related cookies
func extractSessionCookie(r *http.Request) string {
	sessionCookieNames := []string{"sessionid", "session", "SESSIONID", "SESSION", "PHPSESSID", "JSESSIONID", "connect.sid"}
	
	for _, name := range sessionCookieNames {
		if cookie, err := r.Cookie(name); err == nil {
			return hashString(cookie.Value)
		}
	}
	return ""
}

// isAuthCookie checks if a cookie name indicates authentication
func isAuthCookie(name string) bool {
	authPatterns := []string{"auth", "token", "session", "login", "user", "jwt", "bearer"}
	nameLower := strings.ToLower(name)
	
	for _, pattern := range authPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// hashString creates a SHA256 hash of a string for privacy
func hashString(s string) string {
	if s == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])[:16] // First 16 chars for brevity
}

// generateFingerprintHash creates a unique hash for the fingerprint
func generateFingerprintHash(fp *ClientFingerprint) string {
	h := sha256.New()
	
	// Add core identifying information
	h.Write([]byte(fp.ClientIP))
	h.Write([]byte(fp.UserAgent))
	h.Write([]byte(fp.SessionCookie))
	h.Write([]byte(fp.Authorization))
	
	// Add auth cookies
	for name, value := range fp.AuthCookies {
		h.Write([]byte(name + ":" + value))
	}
	
	// Add session tokens
	for name, value := range fp.SessionTokens {
		h.Write([]byte(name + ":" + value))
	}
	
	// Add stable browser characteristics
	h.Write([]byte(fp.AcceptLanguage))
	h.Write([]byte(fp.AcceptEncoding))
	h.Write([]byte(fp.Host))
	
	hash := h.Sum(nil)
	return hex.EncodeToString(hash)[:24] // Use first 24 chars
}

// calculateFingerprintConfidence calculates confidence score for fingerprint
func calculateFingerprintConfidence(fp *ClientFingerprint) float64 {
	confidence := 0.1 // Base confidence
	
	// Authentication signals (highest weight)
	if fp.Authorization != "" {
		confidence += 0.4
	}
	if fp.SessionCookie != "" {
		confidence += 0.3
	}
	if len(fp.AuthCookies) > 0 {
		confidence += 0.2
	}
	if len(fp.SessionTokens) > 0 {
		confidence += 0.2
	}
	
	// IP consistency
	if fp.ClientIP != "" && net.ParseIP(fp.ClientIP) != nil {
		confidence += 0.1
	}
	
	// Browser fingerprinting
	if fp.UserAgent != "" {
		confidence += 0.1
	}
	if fp.AcceptLanguage != "" {
		confidence += 0.05
	}
	
	// Application context
	if fp.Origin != "" || fp.Referer != "" {
		confidence += 0.05
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// TrackClient tracks a new client or updates existing tracking
func (ct *ClientTracker) TrackClient(r *http.Request) string {
	fingerprint := extractFingerprint(r)
	clientKey := fingerprint.FingerprintHash
	
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	// Get or create session
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		// Check if we're at capacity
		if len(ct.clientSessions) >= ct.maxSessions {
			ct.evictOldestSession()
		}
		
		session = &ClientSession{
			ID:             clientKey,
			Fingerprint:    fingerprint,
			LastSeen:       time.Now(),
			TunnelMappings: make(map[string]int),
			SuccessRate:    make(map[string]float64),
			Confidence:     fingerprint.Confidence,
		}
		ct.clientSessions[clientKey] = session
	} else {
		// Update existing session
		session.LastSeen = time.Now()
		session.Fingerprint = fingerprint
		if fingerprint.Confidence > session.Confidence {
			session.Confidence = fingerprint.Confidence
		}
	}
	
	// Update IP mappings
	if fingerprint.ClientIP != "" {
		ct.addIPMapping(fingerprint.ClientIP, clientKey)
	}
	
	return clientKey
}

// addIPMapping adds client to IP mapping (assumes lock held)
func (ct *ClientTracker) addIPMapping(clientIP, clientKey string) {
	clients := ct.ipMappings[clientIP]
	for _, existing := range clients {
		if existing == clientKey {
			return // Already mapped
		}
	}
	ct.ipMappings[clientIP] = append(clients, clientKey)
}

// evictOldestSession removes the oldest client session (assumes lock held)
func (ct *ClientTracker) evictOldestSession() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, session := range ct.clientSessions {
		if oldestKey == "" || session.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = session.LastSeen
		}
	}
	
	if oldestKey != "" {
		session := ct.clientSessions[oldestKey]
		delete(ct.clientSessions, oldestKey)
		delete(ct.recentMappings, oldestKey)
		
		// Clean up IP mappings
		if session.Fingerprint != nil {
			ct.removeFromIPMappings(session.Fingerprint.ClientIP, oldestKey)
		}
	}
}

// GetBestTunnel returns the best tunnel for a client based on tracking data
func (ct *ClientTracker) GetBestTunnel(clientKey string) string {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	// Check recent mappings first (fast path)
	if tunnelID, exists := ct.recentMappings[clientKey]; exists {
		return tunnelID
	}
	
	// Check client session
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		return ""
	}
	
	// Find tunnel with highest success rate and usage
	var bestTunnel string
	var bestScore float64
	
	for tunnelID, usageCount := range session.TunnelMappings {
		if usageCount == 0 {
			continue
		}
		
		successRate := session.SuccessRate[tunnelID]
		if successRate == 0 {
			successRate = 0.5 // Neutral score for new tunnels
		}
		
		// Score = success_rate * log(usage_count + 1)
		// This favors both reliable and frequently used tunnels
		score := successRate * (1.0 + float64(usageCount)*0.1)
		
		if score > bestScore {
			bestScore = score
			bestTunnel = tunnelID
		}
	}
	
	return bestTunnel
}

// GetConfidence returns routing confidence for a client-tunnel pair
func (ct *ClientTracker) GetConfidence(clientKey, tunnelID string) float64 {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		return 0.0
	}
	
	usageCount := session.TunnelMappings[tunnelID]
	successRate := session.SuccessRate[tunnelID]
	
	if usageCount == 0 {
		return 0.0
	}
	
	// Confidence increases with usage and success rate
	baseConfidence := session.Confidence
	usageBonus := float64(usageCount) * 0.05
	successBonus := successRate * 0.3
	
	confidence := baseConfidence + usageBonus + successBonus
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// RecordSuccess updates tracking for successful routing
func (ct *ClientTracker) RecordSuccess(clientKey, tunnelID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	// Update recent mappings
	ct.recentMappings[clientKey] = tunnelID
	
	// Update session tracking
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		return
	}
	
	session.LastSeen = time.Now()
	
	// Update usage count
	session.TunnelMappings[tunnelID]++
	
	// Update success rate using exponential moving average
	currentSuccessRate := session.SuccessRate[tunnelID]
	if currentSuccessRate == 0 {
		session.SuccessRate[tunnelID] = 1.0
	} else {
		// EMA with alpha = 0.1 (gives more weight to recent success)
		session.SuccessRate[tunnelID] = currentSuccessRate*0.9 + 1.0*0.1
	}
	
	// Update tunnel->clients mapping
	ct.addTunnelClient(tunnelID, clientKey)
}

// RecordFailure updates tracking for failed routing
func (ct *ClientTracker) RecordFailure(clientKey, tunnelID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		return
	}
	
	session.LastSeen = time.Now()
	
	// Update success rate (failure)
	currentSuccessRate := session.SuccessRate[tunnelID]
	if currentSuccessRate == 0 {
		session.SuccessRate[tunnelID] = 0.0
	} else {
		// EMA with alpha = 0.1 (failure)
		session.SuccessRate[tunnelID] = currentSuccessRate*0.9 + 0.0*0.1
	}
	
	// Remove from recent mappings if it was there
	if ct.recentMappings[clientKey] == tunnelID {
		delete(ct.recentMappings, clientKey)
	}
}

// LearnMapping records a new client-tunnel association
func (ct *ClientTracker) LearnMapping(clientKey, tunnelID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		return
	}
	
	session.LastSeen = time.Now()
	
	// Initialize mapping if not exists
	if _, exists := session.TunnelMappings[tunnelID]; !exists {
		session.TunnelMappings[tunnelID] = 1
		session.SuccessRate[tunnelID] = 0.8 // Initial optimistic score
	} else {
		session.TunnelMappings[tunnelID]++
	}
	
	// Add to recent mappings
	ct.recentMappings[clientKey] = tunnelID
	
	// Update tunnel->clients mapping
	ct.addTunnelClient(tunnelID, clientKey)
}

// addTunnelClient adds client to tunnel's client list (assumes lock held)
func (ct *ClientTracker) addTunnelClient(tunnelID, clientKey string) {
	clients := ct.tunnelClients[tunnelID]
	for _, existing := range clients {
		if existing == clientKey {
			return // Already in list
		}
	}
	ct.tunnelClients[tunnelID] = append(clients, clientKey)
}

// CleanupExpiredSessions removes old client sessions
func (ct *ClientTracker) CleanupExpiredSessions() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	
	now := time.Now()
	var expiredKeys []string
	
	// Find expired sessions
	for clientKey, session := range ct.clientSessions {
		if now.Sub(session.LastSeen) > ct.sessionTTL {
			expiredKeys = append(expiredKeys, clientKey)
		}
	}
	
	// Remove expired sessions
	for _, key := range expiredKeys {
		delete(ct.clientSessions, key)
		delete(ct.recentMappings, key)
		
		// Clean up reverse mappings
		if session := ct.clientSessions[key]; session != nil && session.Fingerprint != nil {
			ct.removeFromIPMappings(session.Fingerprint.ClientIP, key)
		}
	}
	
	// Cleanup tunnel->clients mappings for removed clients
	for tunnelID, clients := range ct.tunnelClients {
		var activeClients []string
		for _, clientKey := range clients {
			if _, exists := ct.clientSessions[clientKey]; exists {
				activeClients = append(activeClients, clientKey)
			}
		}
		ct.tunnelClients[tunnelID] = activeClients
	}
	
	log.Printf("ClientTracker: cleaned up %d expired sessions", len(expiredKeys))
}

// removeFromIPMappings removes client key from IP mappings (assumes lock held)
func (ct *ClientTracker) removeFromIPMappings(clientIP, clientKey string) {
	if clientIP == "" {
		return
	}
	
	clients := ct.ipMappings[clientIP]
	var activeClients []string
	for _, key := range clients {
		if key != clientKey {
			activeClients = append(activeClients, key)
		}
	}
	
	if len(activeClients) == 0 {
		delete(ct.ipMappings, clientIP)
	} else {
		ct.ipMappings[clientIP] = activeClients
	}
}

// GetClientStats returns statistics about client tracking
func (ct *ClientTracker) GetClientStats() map[string]interface{} {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_sessions":  len(ct.clientSessions),
		"recent_mappings": len(ct.recentMappings),
		"tracked_ips":     len(ct.ipMappings),
		"active_tunnels":  len(ct.tunnelClients),
		"session_ttl":     ct.sessionTTL.String(),
		"max_sessions":    ct.maxSessions,
	}
	
	// Confidence distribution
	confidenceRanges := map[string]int{
		"high (0.7-1.0)":   0,
		"medium (0.3-0.7)": 0,
		"low (0.0-0.3)":    0,
	}
	
	for _, session := range ct.clientSessions {
		conf := session.Confidence
		if conf > 0.7 {
			confidenceRanges["high (0.7-1.0)"]++
		} else if conf >= 0.3 {
			confidenceRanges["medium (0.3-0.7)"]++
		} else {
			confidenceRanges["low (0.0-0.3)"]++
		}
	}
	
	stats["confidence_distribution"] = confidenceRanges
	
	return stats
}

// extractTunnelFromReferer extracts tunnel ID from HTTP Referer header
func extractTunnelFromReferer(r *http.Request) string {
	referer := r.Header.Get("Referer")
	if referer == "" {
		return ""
	}
	
	// Parse the referer URL
	refURL, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	
	// Look for /__pub__/{tunnelID}/ pattern
	re := regexp.MustCompile(`^/__pub__/([a-f0-9\-]+)(/.*)?$`)
	matches := re.FindStringSubmatch(refURL.Path)
	if len(matches) >= 2 {
		return matches[1]
	}
	
	return ""
}

// getActiveTunnelIDs returns list of currently active tunnel IDs
func getActiveTunnelIDs() []string {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	
	tunnelIDs := make([]string, 0, len(agents))
	for id := range agents {
		tunnelIDs = append(tunnelIDs, id)
	}
	return tunnelIDs
}

// tryTunnelRoute attempts to route the request through a specific tunnel (legacy version)
func tryTunnelRoute(w http.ResponseWriter, r *http.Request, tunnelID string) bool {
	return tryTunnelRouteWithTimeout(w, r, tunnelID, false)
}

// tryTunnelRouteWithTimeout attempts to route the request through a specific tunnel with configurable timeout
func tryTunnelRouteWithTimeout(w http.ResponseWriter, r *http.Request, tunnelID string, isAsset bool) bool {
	ac := getAgent(tunnelID)
	if ac == nil {
		log.Printf("Smart routing: tryTunnelRoute FAILED - no agent found for tunnel %s (path: %s)", tunnelID, r.URL.Path)
		return false
	}
	
	// Prepare the request path (remove leading slash if present)
	requestPath := strings.TrimPrefix(r.URL.Path, "/")
	if requestPath == "" {
		requestPath = "/"
	} else {
		requestPath = "/" + requestPath
	}
	
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	
	reqID := uuid.NewString()
	req := &ReqFrame{
		Type:    "req",
		ReqID:   reqID,
		Method:  r.Method,
		Path:    requestPath,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		Body:    body,
	}
	
	respCh := make(chan *RespFrame, 1)
	ac.registerWaiter(reqID, respCh)
	
	// Use different timeouts for assets vs regular requests
	timeout := 5 * time.Second
	if isAsset {
		timeout = 15 * time.Second // Longer timeout for asset requests
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	
	// Send encrypted request
	if err := ac.writeEncrypted(ctx, req); err != nil {
		log.Printf("Smart routing: FAILED to write encrypted request to tunnel %s for path %s: %v", tunnelID, r.URL.Path, err)
		return false
	}
	
	select {
	case resp := <-respCh:
		// Check if response is successful (2xx status)
		if resp.Status >= 200 && resp.Status < 300 {
			// Cache successful mapping for assets
			if isAsset {
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = tunnelID
				assetCacheMu.Unlock()
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
			return true
		}
		log.Printf("Smart routing: tunnel %s returned non-2xx status %d for %s (method: %s, isAsset: %v)", tunnelID, resp.Status, r.URL.Path, r.Method, isAsset)
		return false
	case <-ctx.Done():
		log.Printf("Smart routing: TIMEOUT waiting for response from tunnel %s for %s (method: %s, timeout: %v)", tunnelID, r.URL.Path, r.Method, timeout)
		return false
	}
}
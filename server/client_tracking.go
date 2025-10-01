package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

const (
	// TunnelAffinityWindow is the time window for immediate tunnel affinity
	// Based on user behavior: no one opens multiple custom/public URLs within 2 seconds
	TunnelAffinityWindow = 2 * time.Second
)

// NewClientTracker creates a new client tracker with default settings
func NewClientTracker() *ClientTracker {
	return &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]*RecentMapping),
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

// generateFingerprintHash creates a unique hash for the fingerprint using ultra-stable elements
func generateFingerprintHash(fp *ClientFingerprint) string {
	h := sha256.New()

	// ULTRA-STABLE CORE ELEMENTS - absolute minimum for maximum stability
	// These are the ONLY elements that remain consistent across all request types
	h.Write([]byte(fp.ClientIP))
	h.Write([]byte(fp.UserAgent))

	// NOTE: Removed AcceptLanguage and Host because they can vary in some browsers:
	// - AcceptLanguage: May change between requests due to browser settings
	// - Host: May include different ports or protocols
	// - Session cookies: Excluded for stability (appear/disappear during session)
	// - All other headers: Too volatile for reliable fingerprinting
	//
	// This ultra-minimal approach ensures maximum session continuity
	// at the cost of some fingerprint granularity, which is acceptable
	// for preventing cross-contamination.

	hash := h.Sum(nil)
	return hex.EncodeToString(hash)[:24] // Use first 24 chars
}

// calculateFingerprintConfidence calculates confidence score for fingerprint
func calculateFingerprintConfidence(fp *ClientFingerprint) float64 {
	confidence := 0.1 // Base confidence
	var confidenceDetails []string

	// Authentication signals (highest weight)
	if fp.Authorization != "" {
		confidence += 0.4
		confidenceDetails = append(confidenceDetails, "auth_header:+0.4")
	}
	if fp.SessionCookie != "" {
		confidence += 0.3
		confidenceDetails = append(confidenceDetails, "session_cookie:+0.3")
	}
	if len(fp.AuthCookies) > 0 {
		confidence += 0.2
		confidenceDetails = append(confidenceDetails, fmt.Sprintf("auth_cookies(%d):+0.2", len(fp.AuthCookies)))
	}
	if len(fp.SessionTokens) > 0 {
		confidence += 0.2
		confidenceDetails = append(confidenceDetails, fmt.Sprintf("session_tokens(%d):+0.2", len(fp.SessionTokens)))
	}

	// IP consistency
	if fp.ClientIP != "" && net.ParseIP(fp.ClientIP) != nil {
		confidence += 0.1
		confidenceDetails = append(confidenceDetails, "valid_ip:+0.1")
	}

	// Browser fingerprinting
	if fp.UserAgent != "" {
		confidence += 0.1
		confidenceDetails = append(confidenceDetails, "user_agent:+0.1")
	}
	if fp.AcceptLanguage != "" {
		confidence += 0.05
		confidenceDetails = append(confidenceDetails, "accept_lang:+0.05")
	}

	// Application context
	if fp.Origin != "" || fp.Referer != "" {
		confidence += 0.05
		confidenceDetails = append(confidenceDetails, "origin_referer:+0.05")
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	log.Printf("[FINGERPRINT QUALITY] Confidence calculated | Hash: %s | IP: %s | Confidence: %.2f | Details: %v",
		fp.FingerprintHash, fp.ClientIP, confidence, confidenceDetails)

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

	log.Printf("[TUNNEL SELECTION] Starting best tunnel selection | ClientKey: %s", clientKey)

	// PRIORITY 1: Check 2-second tunnel affinity window (immediate routing)
	if recentMapping, exists := ct.recentMappings[clientKey]; exists {
		age := time.Since(recentMapping.Timestamp)
		if age <= TunnelAffinityWindow {
			log.Printf("[TUNNEL AFFINITY] Using recent mapping | ClientKey: %s | TunnelID: %s | Age: %v | AccessType: %s",
				clientKey, recentMapping.TunnelID, age, recentMapping.AccessType)
			return recentMapping.TunnelID
		} else {
			// Mapping expired, log for debugging
			log.Printf("[TUNNEL AFFINITY] Recent mapping expired | ClientKey: %s | TunnelID: %s | Age: %v | Threshold: %v",
				clientKey, recentMapping.TunnelID, age, TunnelAffinityWindow)
		}
	} else {
		log.Printf("[TUNNEL AFFINITY] No recent mapping found | ClientKey: %s", clientKey)
	}

	// Check client session
	session, exists := ct.clientSessions[clientKey]
	if !exists {
		log.Printf("[TUNNEL SELECTION] No client session found | ClientKey: %s", clientKey)
		return ""
	}

	log.Printf("[TUNNEL SELECTION] Client session found | ClientKey: %s | TunnelMappings: %v | SuccessRates: %v | Confidence: %.2f",
		clientKey, session.TunnelMappings, session.SuccessRate, session.Confidence)

	// Find tunnel with highest success rate and usage
	var bestTunnel string
	var bestScore float64
	var allScores = make(map[string]float64)

	for tunnelID, usageCount := range session.TunnelMappings {
		if usageCount == 0 {
			log.Printf("[TUNNEL SELECTION] Skipping tunnel with zero usage | TunnelID: %s", tunnelID)
			continue
		}

		successRate := session.SuccessRate[tunnelID]
		if successRate == 0 {
			successRate = 0.5 // Neutral score for new tunnels
		}

		// Score = success_rate * log(usage_count + 1)
		// This favors both reliable and frequently used tunnels
		score := successRate * (1.0 + float64(usageCount)*0.1)
		allScores[tunnelID] = score

		log.Printf("[TUNNEL SELECTION] Evaluating tunnel | TunnelID: %s | UsageCount: %d | SuccessRate: %.2f | Score: %.2f",
			tunnelID, usageCount, successRate, score)

		if score > bestScore {
			bestScore = score
			bestTunnel = tunnelID
		}
	}

	if bestTunnel != "" {
		log.Printf("[TUNNEL SELECTION] Best tunnel selected | ClientKey: %s | TunnelID: %s | Score: %.2f | AllScores: %v",
			clientKey, bestTunnel, bestScore, allScores)
	} else {
		log.Printf("[TUNNEL SELECTION] No suitable tunnel found | ClientKey: %s | AllScores: %v", clientKey, allScores)
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

// CreateImmediateBinding creates a 2-second tunnel affinity for immediate follow-up requests
func (ct *ClientTracker) CreateImmediateBinding(clientKey, tunnelID, accessType string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Check if there's an existing recent mapping
	var previousMapping string
	if existing, exists := ct.recentMappings[clientKey]; exists {
		age := time.Since(existing.Timestamp)
		previousMapping = fmt.Sprintf("previous:%s(age:%v)", existing.TunnelID, age)
	}

	recentMapping := &RecentMapping{
		TunnelID:   tunnelID,
		Timestamp:  time.Now(),
		AccessType: accessType,
	}

	ct.recentMappings[clientKey] = recentMapping

	log.Printf("[TUNNEL AFFINITY] Created immediate binding | ClientKey: %s | TunnelID: %s | AccessType: %s | Window: %v | %s",
		clientKey, tunnelID, accessType, TunnelAffinityWindow, previousMapping)
}

// RecordSuccess updates tracking for successful routing
func (ct *ClientTracker) RecordSuccess(clientKey, tunnelID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Update recent mappings with timestamp (extend existing or create new)
	recentMapping := &RecentMapping{
		TunnelID:   tunnelID,
		Timestamp:  time.Now(),
		AccessType: "success_routing",
	}
	ct.recentMappings[clientKey] = recentMapping

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
	if recentMapping, exists := ct.recentMappings[clientKey]; exists && recentMapping.TunnelID == tunnelID {
		delete(ct.recentMappings, clientKey)
		log.Printf("[TUNNEL AFFINITY] Removed failed mapping | ClientKey: %s | TunnelID: %s", clientKey, tunnelID)
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

	// Add to recent mappings with timestamp
	recentMapping := &RecentMapping{
		TunnelID:   tunnelID,
		Timestamp:  time.Now(),
		AccessType: "learned_mapping",
	}
	ct.recentMappings[clientKey] = recentMapping

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

// CleanupExpiredRecentMappings removes recent mappings older than the affinity window
func (ct *ClientTracker) CleanupExpiredRecentMappings() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	now := time.Now()
	var expiredKeys []string

	for clientKey, recentMapping := range ct.recentMappings {
		age := now.Sub(recentMapping.Timestamp)
		if age > TunnelAffinityWindow {
			expiredKeys = append(expiredKeys, clientKey)
		}
	}

	for _, key := range expiredKeys {
		mapping := ct.recentMappings[key]
		delete(ct.recentMappings, key)
		log.Printf("[TUNNEL AFFINITY] Cleaned up expired mapping | ClientKey: %s | TunnelID: %s | Age: %v | AccessType: %s",
			key, mapping.TunnelID, now.Sub(mapping.Timestamp), mapping.AccessType)
	}

	if len(expiredKeys) > 0 {
		log.Printf("[TUNNEL AFFINITY] Cleaned up %d expired recent mappings", len(expiredKeys))
	}
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
		// Only include HTTP tunnels for smart routing (exclude TCP tunnels)
		tunnelsMu.RLock()
		tunnel, exists := tunnels[id]
		tunnelsMu.RUnlock()

		if !exists || tunnel.Protocol != "tcp" {
			tunnelIDs = append(tunnelIDs, id)
		}
	}
	return tunnelIDs
}

// tryTunnelRouteWithBufferedBody attempts to route the request through a specific tunnel using pre-buffered body
func tryTunnelRouteWithBufferedBody(w http.ResponseWriter, r *http.Request, bodyBytes []byte, tunnelID string, isAsset bool) bool {
	startTime := time.Now()

	// RACE CONDITION FIX: Retry getting agent during tunnel reconnection window
	var ac *agentConn
	maxRetries := 3
	retryDelay := 50 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		ac = getAgent(tunnelID)
		if ac != nil {
			if attempt > 0 {
				log.Printf("[TUNNEL ROUTING] Agent reconnection successful after %d retries | TunnelID: %s | Path: %s",
					attempt, tunnelID, r.URL.Path)
			}
			break
		}

		if attempt < maxRetries-1 {
			log.Printf("[TUNNEL ROUTING] Agent not found, retrying in %v | TunnelID: %s | Path: %s | Attempt: %d/%d",
				retryDelay, tunnelID, r.URL.Path, attempt+1, maxRetries)
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
		}
	}

	if ac == nil {
		log.Printf("[TUNNEL ROUTING] FAILED - no agent found after %d retries | TunnelID: %s | Path: %s | Method: %s | Asset: %v",
			maxRetries, tunnelID, r.URL.Path, r.Method, isAsset)
		return false
	}

	log.Printf("[TUNNEL ROUTING] Starting tunnel attempt (buffered body) | TunnelID: %s | Path: %s | Method: %s | Asset: %v | BodySize: %d | Agent connected: %v",
		tunnelID, r.URL.Path, r.Method, isAsset, len(bodyBytes), ac.connectedAt)

	// Validate that this is an HTTP tunnel (not TCP)
	tunnelsMu.RLock()
	tunnel, exists := tunnels[tunnelID]
	tunnelsMu.RUnlock()

	if exists && tunnel.Protocol == "tcp" {
		log.Printf("[TUNNEL ROUTING] FAILED - Cannot route HTTP request to TCP tunnel | TunnelID: %s | Path: %s", tunnelID, r.URL.Path)
		return false // This will trigger fallback to other routing strategies
	}

	// Prepare the request path (remove leading slash if present)
	requestPath := strings.TrimPrefix(r.URL.Path, "/")
	if requestPath == "" {
		requestPath = "/"
	} else {
		requestPath = "/" + requestPath
	}

	reqID := uuid.NewString()
	
	// DIAGNOSTIC: Log routing path entry
	log.Printf("[ROUTING PATH] SMART ROUTING entered for %s -> tunnel %s | ContentType: %s | UserAgent: %s | ReqID: %s", 
		r.URL.Path, tunnelID, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), reqID)

	// Detect WebSocket upgrade requests
	isWebSocketUpgrade := strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
		r.Method == "GET"

	// Detect streaming requests for buffer sizing and timeout logic
	isStreamingRequest := strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		strings.Contains(r.Header.Get("Accept"), "text/stream") ||
		strings.Contains(r.Header.Get("Accept"), "application/stream") ||
		strings.Contains(r.Header.Get("Content-Type"), "text/event-stream") ||
		strings.Contains(r.URL.Path, "/api/agents/") || // AI endpoints are likely streaming
		strings.Contains(r.URL.Path, "/stream") ||
		strings.Contains(r.URL.Path, "/chat")

	req := &ReqFrame{
		Type:    "req",
		ReqID:   reqID,
		Method:  r.Method,
		Path:    requestPath,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		Body:    bodyBytes, // Use buffered body instead of consuming r.Body
	}

	// Handle WebSocket upgrade requests
	if isWebSocketUpgrade {
		log.Printf("[TUNNEL ROUTING] WebSocket upgrade detected | TunnelID: %s | Path: %s | ReqID: %s",
			tunnelID, r.URL.Path, reqID)
		// Use the same WebSocket upgrade handler from handlers.go
		handleWebSocketUpgrade(w, r, req, ac, reqID)
		return true // Successfully handled
	}

	// Use larger buffer for streaming responses to prevent channel blocking
	bufferSize := 1
	if isStreamingRequest {
		bufferSize = 100 // Much larger buffer for streaming chunks
	}
	respCh := make(chan *RespFrame, bufferSize)
	ac.registerWaiter(reqID, respCh)

	// Use timeout only for non-streaming requests
	var ctx context.Context
	var cancel context.CancelFunc

	if isStreamingRequest {
		// No artificial timeout for streaming - let client control connection lifecycle
		ctx = r.Context()
		log.Printf("[TUNNEL ROUTING] Using client-controlled timeout for streaming request | TunnelID: %s | Path: %s | Method: %s",
			tunnelID, r.URL.Path, r.Method)
	} else {
		// Regular requests get timeouts based on type
		timeout := 5 * time.Second
		if isAsset {
			timeout = 15 * time.Second // Longer timeout for asset requests
		}
		ctx, cancel = context.WithTimeout(r.Context(), timeout)
		defer cancel()
	}

	// Send encrypted request
	if err := ac.writeEncrypted(ctx, req); err != nil {
		duration := time.Since(startTime)
		log.Printf("[TUNNEL ROUTING] FAILED to write encrypted request (buffered) | TunnelID: %s | Path: %s | Error: %v | Duration: %v",
			tunnelID, r.URL.Path, err, duration)
		return false
	}

	if isStreamingRequest {
		log.Printf("[TUNNEL ROUTING] Request sent (buffered), waiting for response | TunnelID: %s | Path: %s | Timeout: client-controlled",
			tunnelID, r.URL.Path)
	} else {
		timeout := 5 * time.Second
		if isAsset {
			timeout = 15 * time.Second
		}
		log.Printf("[TUNNEL ROUTING] Request sent (buffered), waiting for response | TunnelID: %s | Path: %s | Timeout: %v",
			tunnelID, r.URL.Path, timeout)
	}

	select {
	case resp := <-respCh:
		// DIAGNOSTIC: Log the exact response received
		log.Printf("[TUNNEL ROUTING] Response received from agent | TunnelID: %s | Path: %s | Type: '%s' | Status: %d | Headers: %+v",
			tunnelID, r.URL.Path, resp.Type, resp.Status, resp.Headers)

		statusCode := resp.Status
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		// Check if this is a streaming response
		if resp.Type == "streaming_start" {
			log.Printf("[TUNNEL ROUTING] Starting streaming response | TunnelID: %s | Path: %s | Status: %d",
				tunnelID, r.URL.Path, statusCode)

			// DIAGNOSTIC: Log headers received from agent before setting them
			log.Printf("[TUNNEL ROUTING] Headers received from agent | TunnelID: %s | Path: %s | Headers: %+v",
				tunnelID, r.URL.Path, resp.Headers)

			// DIAGNOSTIC: Check content-type specifically
			if contentType, exists := resp.Headers["Content-Type"]; exists {
				log.Printf("[TUNNEL ROUTING] Content-Type from agent | TunnelID: %s | Path: %s | ContentType: %v",
					tunnelID, r.URL.Path, contentType)
			} else {
				log.Printf("[TUNNEL ROUTING] No Content-Type header from agent | TunnelID: %s | Path: %s",
					tunnelID, r.URL.Path)
			}

			// Set headers for streaming
			for k, vs := range resp.Headers {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}

			// CRITICAL FIX: Ensure Content-Type is explicitly set to prevent Go's auto-detection
			// Go's net/http automatically sets Content-Type if none exists when WriteHeader() is called
			if contentTypeHeaders := w.Header().Values("Content-Type"); len(contentTypeHeaders) == 0 {
				// No Content-Type header found, set default for streaming
				w.Header().Set("Content-Type", "text/event-stream")
				log.Printf("[TUNNEL ROUTING] CONTENT-TYPE FIX - No Content-Type found, setting default | TunnelID: %s | Path: %s", tunnelID, r.URL.Path)
			} else {
				// Content-Type exists, ensure it's properly set (not just added)
				existingContentType := contentTypeHeaders[0]
				w.Header().Set("Content-Type", existingContentType)
				log.Printf("[TUNNEL ROUTING] CONTENT-TYPE FIX - Reinforcing existing Content-Type | TunnelID: %s | Path: %s | ContentType: %s", tunnelID, r.URL.Path, existingContentType)
			}

			// DIAGNOSTIC: Log headers after Content-Type protection
			log.Printf("[TUNNEL ROUTING] Headers set on response writer (after Content-Type fix) | TunnelID: %s | Path: %s | Headers: %+v",
				tunnelID, r.URL.Path, w.Header())

			w.WriteHeader(statusCode)

			// DIAGNOSTIC: Log final response headers after WriteHeader
			log.Printf("[TUNNEL ROUTING] Final response headers sent to client | TunnelID: %s | Path: %s | Status: %d | Headers: %+v",
				tunnelID, r.URL.Path, statusCode, w.Header())

			// Flush headers to start streaming
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

			// Stream chunks in real-time
			totalSize := int64(0)
			for {
				select {
				case chunk := <-respCh:
					// DIAGNOSTIC: Log every chunk received
					log.Printf("[TUNNEL ROUTING] Received chunk from channel | TunnelID: %s | Path: %s | Type: '%s' | Size: %d bytes",
						tunnelID, r.URL.Path, chunk.Type, len(chunk.Body))

					if chunk.Type == "streaming_chunk" {
						log.Printf("[TUNNEL ROUTING] Writing streaming chunk (%d bytes) | TunnelID: %s | Path: %s",
							len(chunk.Body), tunnelID, r.URL.Path)
						n, err := w.Write(chunk.Body)
						if err != nil {
							log.Printf("[TUNNEL ROUTING] Error writing streaming chunk | TunnelID: %s | Path: %s | Error: %v",
								tunnelID, r.URL.Path, err)
							return false
						}
						totalSize += int64(n)

						// Flush immediately for real-time streaming
						if flusher, ok := w.(http.Flusher); ok {
							flusher.Flush()
						}
					} else if chunk.Type == "streaming_end" {
						duration := time.Since(startTime)
						log.Printf("[TUNNEL ROUTING] STREAMING SUCCESS | TunnelID: %s | Path: %s | Status: %d | TotalSize: %d | Duration: %v",
							tunnelID, r.URL.Path, statusCode, totalSize, duration)
						return true
					} else {
						// DIAGNOSTIC: Log unexpected chunk type
						log.Printf("[TUNNEL ROUTING] Unexpected chunk type | TunnelID: %s | Path: %s | Type: '%s' | Expected: 'streaming_chunk' or 'streaming_end'",
							tunnelID, r.URL.Path, chunk.Type)
					}
				case <-ctx.Done():
					log.Printf("[TUNNEL ROUTING] STREAMING TIMEOUT | TunnelID: %s | Path: %s", tunnelID, r.URL.Path)
					return false
				}
			}
		} else {
			// Handle regular (non-streaming) response
			// DIAGNOSTIC: Log why this is being treated as a regular response
			log.Printf("[TUNNEL ROUTING] Treating as regular response (not streaming) | TunnelID: %s | Path: %s | Type: '%s' | Expected: 'streaming_start'",
				tunnelID, r.URL.Path, resp.Type)

			duration := time.Since(startTime)
			bodySize := len(resp.Body)

			// DIAGNOSTIC: Log headers for regular responses too
			log.Printf("[TUNNEL ROUTING] Regular response headers from agent | TunnelID: %s | Path: %s | Headers: %+v",
				tunnelID, r.URL.Path, resp.Headers)

			// DIAGNOSTIC: Check content-type for regular responses
			if contentType, exists := resp.Headers["Content-Type"]; exists {
				log.Printf("[TUNNEL ROUTING] Regular response Content-Type from agent | TunnelID: %s | Path: %s | ContentType: %v",
					tunnelID, r.URL.Path, contentType)
			}

			// Tunnel routing succeeded - write response regardless of HTTP status
			// The HTTP status code is the application's concern, not the tunnel's
			log.Printf("[TUNNEL ROUTING] SUCCESS (buffered) | TunnelID: %s | Path: %s | Status: %d | BodySize: %d | Duration: %v",
				tunnelID, r.URL.Path, statusCode, bodySize, duration)

			// Write response
			for k, vs := range resp.Headers {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}

			// CRITICAL FIX: Ensure Content-Type is explicitly set to prevent Go's auto-detection
			// This is the MISSING Content-Type protection for regular (non-streaming) responses!
			if contentTypeHeaders := w.Header().Values("Content-Type"); len(contentTypeHeaders) == 0 {
				// No Content-Type header found, set default
				w.Header().Set("Content-Type", "text/event-stream")
				log.Printf("[TUNNEL ROUTING] REGULAR RESPONSE CONTENT-TYPE FIX - No Content-Type found, setting default | TunnelID: %s | Path: %s", tunnelID, r.URL.Path)
			} else {
				// Content-Type exists, ensure it's properly set (not just added)
				existingContentType := contentTypeHeaders[0]
				w.Header().Set("Content-Type", existingContentType)
				log.Printf("[TUNNEL ROUTING] REGULAR RESPONSE CONTENT-TYPE FIX - Reinforcing existing Content-Type | TunnelID: %s | Path: %s | ContentType: %s", tunnelID, r.URL.Path, existingContentType)
			}

			// DIAGNOSTIC: Log headers after setting them for regular responses
			log.Printf("[TUNNEL ROUTING] Regular response headers set on writer | TunnelID: %s | Path: %s | Headers: %+v",
				tunnelID, r.URL.Path, w.Header())

			w.WriteHeader(statusCode)
			_, _ = w.Write(resp.Body)
			return true
		}
	case <-ctx.Done():
		duration := time.Since(startTime)
		if isStreamingRequest {
			log.Printf("[TUNNEL ROUTING] CLIENT DISCONNECT (buffered) | TunnelID: %s | Path: %s | Duration: %v | Method: %s | Asset: %v",
				tunnelID, r.URL.Path, duration, r.Method, isAsset)
		} else {
			timeout := 5 * time.Second
			if isAsset {
				timeout = 15 * time.Second
			}
			log.Printf("[TUNNEL ROUTING] TIMEOUT (buffered) | TunnelID: %s | Path: %s | Duration: %v | Timeout: %v | Method: %s | Asset: %v",
				tunnelID, r.URL.Path, duration, timeout, r.Method, isAsset)
		}
		return false
	}
}

// tryTunnelRouteWithTimeout attempts to route the request through a specific tunnel with configurable timeout
func tryTunnelRouteWithTimeout(w http.ResponseWriter, r *http.Request, tunnelID string, isAsset bool) bool {
	startTime := time.Now()
	ac := getAgent(tunnelID)
	if ac == nil {
		log.Printf("[TUNNEL ROUTING] FAILED - no agent found | TunnelID: %s | Path: %s | Method: %s | Asset: %v",
			tunnelID, r.URL.Path, r.Method, isAsset)
		return false
	}

	log.Printf("[TUNNEL ROUTING] Starting tunnel attempt | TunnelID: %s | Path: %s | Method: %s | Asset: %v | Agent connected: %v",
		tunnelID, r.URL.Path, r.Method, isAsset, ac.connectedAt)

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
		duration := time.Since(startTime)
		log.Printf("[TUNNEL ROUTING] FAILED to write encrypted request | TunnelID: %s | Path: %s | Error: %v | Duration: %v",
			tunnelID, r.URL.Path, err, duration)
		return false
	}

	log.Printf("[TUNNEL ROUTING] Request sent, waiting for response | TunnelID: %s | Path: %s | Timeout: %v",
		tunnelID, r.URL.Path, timeout)

	select {
	case resp := <-respCh:
		duration := time.Since(startTime)
		bodySize := len(resp.Body)

		// Tunnel routing succeeded - write response regardless of HTTP status
		// The HTTP status code is the application's concern, not the tunnel's
		log.Printf("[TUNNEL ROUTING] SUCCESS | TunnelID: %s | Path: %s | Status: %d | BodySize: %d | Duration: %v",
			tunnelID, r.URL.Path, resp.Status, bodySize, duration)

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
	case <-ctx.Done():
		duration := time.Since(startTime)
		log.Printf("[TUNNEL ROUTING] TIMEOUT | TunnelID: %s | Path: %s | Duration: %v | Timeout: %v | Method: %s | Asset: %v",
			tunnelID, r.URL.Path, duration, timeout, r.Method, isAsset)
		return false
	}
}

// Redirection session management for SPA routing

// getSessionKeys returns the keys of a RedirectSessions map for logging
func getSessionKeys(sessions map[string]*RedirectSession) []string {
	keys := make([]string, 0, len(sessions))
	for k := range sessions {
		keys = append(keys, k)
	}
	return keys
}

// getRedirectSession retrieves an active redirection session for a client and custom URL
func getRedirectSession(clientKey, customURL string) *RedirectSession {
	log.Printf("[SESSION LOOKUP] Looking up redirect session | ClientKey: %s | CustomURL: %s", clientKey, customURL)

	clientTracker.mu.RLock()
	defer clientTracker.mu.RUnlock()

	session, exists := clientTracker.clientSessions[clientKey]
	if !exists || session.RedirectSessions == nil {
		log.Printf("[SESSION LOOKUP] No client session found | ClientKey: %s | Exists: %t", clientKey, exists)
		return nil
	}

	log.Printf("[SESSION LOOKUP] Client session found | ClientKey: %s | Available sessions: %v", clientKey, getSessionKeys(session.RedirectSessions))

	// Get the redirect session for this specific custom URL
	redirectSession, exists := session.RedirectSessions[customURL]
	if !exists || !redirectSession.Active {
		log.Printf("[SESSION LOOKUP] No active redirect session | ClientKey: %s | CustomURL: %s | Exists: %t | Active: %t", clientKey, customURL, exists, exists && redirectSession.Active)
		return nil
	}

	// Check TTL
	if time.Since(redirectSession.RedirectTime) > redirectSession.TTL {
		log.Printf("[SESSION LOOKUP] Redirect session expired | ClientKey: %s | CustomURL: %s | Age: %v | TTL: %v", clientKey, customURL, time.Since(redirectSession.RedirectTime), redirectSession.TTL)
		return nil // Expired
	}

	log.Printf("[SESSION LOOKUP] Found active redirect session | ClientKey: %s | CustomURL: %s | TunnelID: %s", clientKey, customURL, redirectSession.TunnelID)
	return redirectSession
}

// createRedirectSession creates a new redirection session for SPA routing
func createRedirectSession(clientKey, customURL, tunnelID string) {
	log.Printf("[SESSION CREATE] Starting redirect session creation | ClientKey: %s | CustomURL: %s | TunnelID: %s", clientKey, customURL, tunnelID)

	clientTracker.mu.Lock()
	defer clientTracker.mu.Unlock()

	// Get or create client session
	session, exists := clientTracker.clientSessions[clientKey]
	if !exists {
		log.Printf("[SESSION CREATE] Creating new client session | ClientKey: %s", clientKey)
		session = &ClientSession{
			ID:               uuid.NewString(),
			LastSeen:         time.Now(),
			TunnelMappings:   make(map[string]int),
			SuccessRate:      make(map[string]float64),
			RedirectSessions: make(map[string]*RedirectSession),
		}
		clientTracker.clientSessions[clientKey] = session
	} else {
		log.Printf("[SESSION CREATE] Using existing client session | ClientKey: %s | Existing sessions: %v", clientKey, getSessionKeys(session.RedirectSessions))
	}

	// Initialize RedirectSessions map if nil
	if session.RedirectSessions == nil {
		session.RedirectSessions = make(map[string]*RedirectSession)
	}

	// Check if session already exists for this custom URL
	if existingSession, exists := session.RedirectSessions[customURL]; exists {
		log.Printf("[SESSION CREATE] Overwriting existing session | ClientKey: %s | CustomURL: %s | OldTunnelID: %s | NewTunnelID: %s", clientKey, customURL, existingSession.TunnelID, tunnelID)
	}

	// Create redirection session with 30-minute TTL for this specific custom URL
	session.RedirectSessions[customURL] = &RedirectSession{
		CustomURL:    customURL,
		TunnelID:     tunnelID,
		RedirectTime: time.Now(),
		LastUsed:     time.Now(),
		RequestCount: 1,
		Active:       true,
		TTL:          30 * time.Minute,
	}

	session.LastSeen = time.Now()

	log.Printf("[SESSION CREATE] Created redirect session | ClientKey: %s | CustomURL: %s | TunnelID: %s | Total sessions: %d", clientKey, customURL, tunnelID, len(session.RedirectSessions))
}

// updateRedirectSession updates the usage statistics for an active redirection session
func updateRedirectSession(redirectSession *RedirectSession) {
	redirectSession.LastUsed = time.Now()
	redirectSession.RequestCount++

	log.Printf("Updated redirection session: customURL=%s, tunnel=%s, requests=%d",
		redirectSession.CustomURL, redirectSession.TunnelID, redirectSession.RequestCount)
}

// getActiveRedirectSession retrieves any active redirection session for a client (regardless of custom URL)
func getActiveRedirectSession(clientKey string) *RedirectSession {
	clientTracker.mu.RLock()
	defer clientTracker.mu.RUnlock()

	session, exists := clientTracker.clientSessions[clientKey]
	if !exists || session.RedirectSessions == nil {
		return nil
	}

	// Find any active redirect session (return the most recently used one)
	var mostRecentSession *RedirectSession
	var mostRecentTime time.Time

	for _, redirectSession := range session.RedirectSessions {
		if redirectSession.Active {
			// Check TTL
			if time.Since(redirectSession.RedirectTime) <= redirectSession.TTL {
				if mostRecentSession == nil || redirectSession.LastUsed.After(mostRecentTime) {
					mostRecentSession = redirectSession
					mostRecentTime = redirectSession.LastUsed
				}
			} else {
				// Deactivate expired sessions
				redirectSession.Active = false
				log.Printf("[REDIRECT SESSION] Deactivated expired session | ClientKey: %s | CustomURL: %s | Age: %v", clientKey, redirectSession.CustomURL, time.Since(redirectSession.RedirectTime))
			}
		}
	}

	return mostRecentSession
}

// getRedirectionStats returns statistics about active redirection sessions
func getRedirectionStats() map[string]interface{} {
	clientTracker.mu.RLock()
	defer clientTracker.mu.RUnlock()

	activeCount := 0
	totalSessions := 0
	sessionsByTunnel := make(map[string]int)
	sessionsByCustomURL := make(map[string]int)
	totalRequests := 0

	for _, session := range clientTracker.clientSessions {
		if session.RedirectSessions != nil {
			for _, redirectSession := range session.RedirectSessions {
				totalSessions++
				totalRequests += redirectSession.RequestCount

				if redirectSession.Active {
					// Check if not expired
					if time.Since(redirectSession.RedirectTime) <= redirectSession.TTL {
						activeCount++
						sessionsByTunnel[redirectSession.TunnelID]++
						sessionsByCustomURL[redirectSession.CustomURL]++
					}
				}
			}
		}
	}

	return map[string]interface{}{
		"active_sessions":        activeCount,
		"total_sessions":         totalSessions,
		"total_requests":         totalRequests,
		"sessions_by_tunnel":     sessionsByTunnel,
		"sessions_by_custom_url": sessionsByCustomURL,
	}
}

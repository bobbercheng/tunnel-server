package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

// getCountryFromIP extracts country from IP address using existing geo functionality
func getCountryFromIP(clientIP string) string {
	geoData := lookupIPGeoData(clientIP)
	if geoData != nil {
		return geoData.Country
	}
	return ""
}

// healthHandler provides server health and connection status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	agentsMu.RLock()
	defer agentsMu.RUnlock()

	type agentInfo struct {
		ID          string `json:"id"`
		ConnectedAt string `json:"connected_at"`
		Encrypted   bool   `json:"encrypted"`
		CustomURL   string `json:"custom_url,omitempty"`
		UseRedirect bool   `json:"use_redirect,omitempty"`
		ClientIP    string `json:"client_ip,omitempty"`
		Country     string `json:"country,omitempty"`
		Region      string `json:"region,omitempty"`
		City        string `json:"city,omitempty"`
	}

	info := struct {
		ActiveConnections   []agentInfo            `json:"active_connections"`
		ConnectionCount     int                    `json:"connection_count"`
		ClientTracking      map[string]interface{} `json:"client_tracking"`
		GeographicalRouting map[string]interface{} `json:"geographical_routing"`
		CustomURLs          map[string]interface{} `json:"custom_urls"`
		RedirectionSessions map[string]interface{} `json:"redirection_sessions"`
		CustomURLAffinity   map[string]interface{} `json:"custom_url_affinity"`
	}{
		ActiveConnections:   make([]agentInfo, 0, len(agents)),
		ConnectionCount:     len(agents),
		ClientTracking:      clientTracker.GetClientStats(),
		GeographicalRouting: getGeoRoutingStats(),
		CustomURLs:          getCustomURLStats(),
		RedirectionSessions: getRedirectionStats(),
		CustomURLAffinity:   getAffinityStats(),
	}

	for id, conn := range agents {
		// Look up custom URL for this tunnel
		tunnelsMu.RLock()
		tunnel := tunnels[id]
		tunnelsMu.RUnlock()

		customURL := ""
		if tunnel != nil && tunnel.CustomURL != "" {
			customURL = tunnel.CustomURL
		}

		// Extract geolocation info
		country := ""
		region := ""
		city := ""
		if conn.geoData != nil {
			country = conn.geoData.Country
			region = conn.geoData.Region
			city = conn.geoData.City
		}

		info.ActiveConnections = append(info.ActiveConnections, agentInfo{
			ID:          id,
			ConnectedAt: conn.connectedAt.Format(time.RFC3339),
			Encrypted:   conn.cipher != nil,
			CustomURL:   customURL,
			UseRedirect: tunnel != nil && tunnel.UseRedirect,
			ClientIP:    conn.clientIP,
			Country:     country,
			Region:      region,
			City:        city,
		})
	}

	writeJSON(w, http.StatusOK, info)
}

// publicHandler handles public HTTP requests through tunnels
func publicHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// /__pub__/{id}/<rest>
	path := strings.TrimPrefix(r.URL.Path, "/__pub__/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	id := parts[0]
	restPath := "/"
	if len(parts) == 2 {
		restPath += parts[1]
	}

	ac := getAgent(id)
	if ac == nil {
		tunnelMetrics.RecordError(id, "agent_not_connected")
		http.Error(w, "agent not connected", http.StatusBadGateway)
		return
	}

	// Validate that this is an HTTP tunnel (not TCP)
	tunnelsMu.RLock()
	tunnel, exists := tunnels[id]
	tunnelsMu.RUnlock()

	if exists && tunnel.Protocol == "tcp" {
		tunnelMetrics.RecordError(id, "http_request_to_tcp_tunnel")
		http.Error(w, "Cannot make HTTP requests to TCP tunnel. Use TCP client to connect to this tunnel.", http.StatusBadRequest)
		return
	}

	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

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

	reqID := uuid.NewString()

	// DIAGNOSTIC: Log routing path entry
	log.Printf("[ROUTING PATH] DIRECT HANDLER entered for %s -> tunnel %s | ContentType: %s | UserAgent: %s | ReqID: %s", 
		r.URL.Path, id, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), reqID)

	req := &ReqFrame{
		Type:    "req",
		ReqID:   reqID,
		Method:  r.Method,
		Path:    restPath,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		Body:    body,
	}

	// Handle WebSocket upgrade requests
	if isWebSocketUpgrade {
		log.Printf("SERVER WEBSOCKET: Upgrade request detected | Path: %s | ReqID: %s",
			r.URL.Path, reqID)
		handleWebSocketUpgrade(w, r, req, ac, reqID)
		return
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
		log.Printf("SERVER: Using client-controlled timeout for streaming request | Path: %s | Method: %s",
			r.URL.Path, r.Method)
	} else {
		// Regular requests get 60-second timeout
		timeout := 60 * time.Second
		ctx, cancel = context.WithTimeout(r.Context(), timeout)
		defer cancel()
	}

	// Send encrypted request
	if err := ac.writeEncrypted(ctx, req); err != nil {
		tunnelMetrics.RecordError(id, "write_failed")
		http.Error(w, "failed to write to agent: "+err.Error(), http.StatusBadGateway)
		return
	}

	select {
	case resp := <-respCh:
		statusCode := resp.Status
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		// Check if this is a streaming response
		if resp.Type == "streaming_start" {
			log.Printf("SERVER: Starting streaming response | ReqID: %s | Status: %d", reqID, statusCode)

			// DIAGNOSTIC: Log headers received from agent
			log.Printf("SERVER: Streaming headers from agent | ReqID: %s | Headers: %+v", reqID, resp.Headers)

			// DIAGNOSTIC: Check content-type specifically
			if contentType, exists := resp.Headers["Content-Type"]; exists {
				log.Printf("SERVER: Streaming Content-Type from agent | ReqID: %s | ContentType: %v", reqID, contentType)
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
				log.Printf("SERVER: CONTENT-TYPE FIX - No Content-Type found, setting default | ReqID: %s", reqID)
			} else {
				// Content-Type exists, ensure it's properly set (not just added)
				existingContentType := contentTypeHeaders[0]
				w.Header().Set("Content-Type", existingContentType)
				log.Printf("SERVER: CONTENT-TYPE FIX - Reinforcing existing Content-Type | ReqID: %s | ContentType: %s", reqID, existingContentType)
			}

			// DIAGNOSTIC: Log headers after Content-Type protection
			log.Printf("SERVER: Streaming headers set on writer (after Content-Type fix) | ReqID: %s | Headers: %+v", reqID, w.Header())

			w.WriteHeader(statusCode)

			// DIAGNOSTIC: Log final response headers after WriteHeader
			log.Printf("SERVER: Final streaming response headers sent to client | ReqID: %s | Status: %d | Headers: %+v",
				reqID, statusCode, w.Header())

			// Flush headers to start streaming
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

			// Record initial metrics
			clientIP := extractRealClientIP(r)
			clientKey := generateClientKey(r)
			clientTracker.RecordSuccess(clientKey, id)
			clientTracker.CreateImmediateBinding(clientKey, id, "public_url")
			recordIPTunnelMapping(clientIP, id)
			if !isAssetRequest(restPath) {
				recordClientAssetMapping(clientKey, id)
			}

			// Stream chunks in real-time
			totalSize := int64(0)
			for {
				select {
				case chunk, ok := <-respCh:
					if !ok {
						// Channel was closed, streaming session ended
						log.Printf("SERVER: Streaming channel closed | ReqID: %s | TotalSize: %d bytes", reqID, totalSize)
						
						// Record final metrics for channel closure
						duration := time.Since(startTime).Seconds()
						requestSize := int64(len(body))
						tunnelMetrics.RecordRequest(id, r.Method, strconv.Itoa(statusCode), duration, requestSize, totalSize)

						// Record geographic request if we have geolocation data
						if country := getCountryFromIP(clientIP); country != "" {
							tunnelMetrics.RecordGeographicRequest(id, country)
						}
						return
					}
					
					if chunk.Type == "streaming_chunk" {
						log.Printf("SERVER: Writing streaming chunk (%d bytes) | ReqID: %s", len(chunk.Body), reqID)
						n, err := w.Write(chunk.Body)
						if err != nil {
							log.Printf("SERVER: Error writing streaming chunk | ReqID: %s | Error: %v", reqID, err)
							return
						}
						totalSize += int64(n)

						// Flush immediately for real-time streaming
						if flusher, ok := w.(http.Flusher); ok {
							flusher.Flush()
						}
					} else if chunk.Type == "streaming_end" {
						log.Printf("SERVER: Streaming response completed with streaming_end | ReqID: %s | TotalSize: %d bytes", reqID, totalSize)

						// Record final metrics
						duration := time.Since(startTime).Seconds()
						requestSize := int64(len(body))
						tunnelMetrics.RecordRequest(id, r.Method, strconv.Itoa(statusCode), duration, requestSize, totalSize)

						// Record geographic request if we have geolocation data
						if country := getCountryFromIP(clientIP); country != "" {
							tunnelMetrics.RecordGeographicRequest(id, country)
						}
						return
					} else {
						log.Printf("SERVER: Unexpected streaming frame type | ReqID: %s | Type: %s", reqID, chunk.Type)
					}
				case <-ctx.Done():
					log.Printf("SERVER: Streaming timeout/cancellation | ReqID: %s", reqID)
					return
				}
			}
		} else {
			// Handle regular (non-streaming) response
			duration := time.Since(startTime).Seconds()
			requestSize := int64(len(body))
			responseSize := int64(len(resp.Body))

			tunnelMetrics.RecordRequest(id, r.Method, strconv.Itoa(statusCode), duration, requestSize, responseSize)

			// Record geographic request if we have geolocation data
			clientIP := extractRealClientIP(r)
			if country := getCountryFromIP(clientIP); country != "" {
				tunnelMetrics.RecordGeographicRequest(id, country)
			}

			// Record successful tunnel access for smart routing learning
			clientKey := generateClientKey(r)
			clientTracker.RecordSuccess(clientKey, id)

			// Create immediate tunnel binding for 2-second affinity window
			clientTracker.CreateImmediateBinding(clientKey, id, "public_url")

			// Record IP-based geographical routing
			recordIPTunnelMapping(clientIP, id)

			// For non-asset requests (main pages), record asset mapping
			if !isAssetRequest(restPath) {
				recordClientAssetMapping(clientKey, id)
			}

			for k, vs := range resp.Headers {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(statusCode)
			_, _ = w.Write(resp.Body)
		}
	case <-ctx.Done():
		tunnelMetrics.RecordError(id, "timeout")
		http.Error(w, "timeout waiting agent", http.StatusGatewayTimeout)
	}
}

// customURLHandler handles custom URL routing with case-sensitive matching
func customURLHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[ROUTING REQUEST] URL: %s | Method: %s | Client IP: %s | User-Agent: %s", r.URL.Path, r.Method, r.RemoteAddr, r.Header.Get("User-Agent"))

	// Skip if this is already a system endpoint
	if strings.HasPrefix(r.URL.Path, "/__pub__/") ||
		strings.HasPrefix(r.URL.Path, "/__ws__") ||
		strings.HasPrefix(r.URL.Path, "/__tcp__/") ||
		strings.HasPrefix(r.URL.Path, "/__health__") {
		log.Printf("[ROUTING DECISION] System endpoint detected: %s | Forwarding to smartFallbackHandler", r.URL.Path)
		smartFallbackHandler(w, r)
		return
	}

	path := strings.Trim(r.URL.Path, "/")

	// Try exact custom URL match first (case-sensitive)
	customURLsMu.RLock()
	tunnelID := customURLs[path]
	allCustomURLs := make(map[string]string)
	for k, v := range customURLs {
		allCustomURLs[k] = v
	}
	customURLsMu.RUnlock()

	log.Printf("[ROUTING LOOKUP] Trimmed path: '%s' | Found tunnel: %s | All custom URLs: %v", path, tunnelID, allCustomURLs)

	if tunnelID != "" {
		log.Printf("[ROUTING MATCH] Custom URL: %s matched tunnel: %s | Original URL: %s", path, tunnelID, r.URL.Path)

		// Calculate forward path first
		var forwardPath string
		if path == strings.Trim(r.URL.Path, "/") {
			forwardPath = "/"
		} else {
			// Extract the part after the custom URL
			remaining := strings.TrimPrefix(r.URL.Path, "/"+path)
			if remaining == "" {
				forwardPath = "/"
			} else {
				forwardPath = remaining
			}
		}

		// Check if this tunnel has redirection enabled
		tunnelsMu.RLock()
		tunnel := tunnels[tunnelID]
		useRedirect := tunnel != nil && tunnel.UseRedirect
		log.Printf("[TUNNEL REDIRECT CONFIG] TunnelID: %s | Tunnel exists: %v | UseRedirect: %v", tunnelID, tunnel != nil, useRedirect)
		tunnelsMu.RUnlock()

		// Validate that this is an HTTP tunnel (not TCP)
		if tunnel != nil && tunnel.Protocol == "tcp" {
			log.Printf("[ROUTING REJECT] TCP tunnel %s cannot handle HTTP requests from custom URL %s", tunnelID, path)
			http.Error(w, "Cannot make HTTP requests to TCP tunnel. Use TCP client to connect to this tunnel.", http.StatusBadRequest)
			return
		}

		// Handle redirection for SPA base path issues
		if useRedirect && forwardPath == "/" {
			// Always redirect when use_redirect is enabled to ensure consistent SPA behavior
			clientKey := generateClientKey(r)
			log.Printf("[REDIRECT ALWAYS] UseRedirect: %t | ForwardPath: %s | ClientKey: %s | RequestURL: %s", useRedirect, forwardPath, clientKey, r.URL.Path)

			// NEW: Set custom URL affinity for persistent routing (even when redirecting)
			clientIP := extractRealClientIP(r)
			affinityManager.SetAffinityWithIP(clientKey, tunnelID, path, "custom_url_redirect", clientIP)

			// Create or update redirection session for analytics tracking
			redirectSession := getRedirectSession(clientKey, path)
			if redirectSession == nil || !redirectSession.Active {
				createRedirectSession(clientKey, path, tunnelID)
				log.Printf("[REDIRECT SESSION] Created new redirect session | ClientKey: %s | CustomURL: %s | TunnelID: %s", clientKey, path, tunnelID)
			} else {
				updateRedirectSession(redirectSession)
				log.Printf("[REDIRECT SESSION] Updated existing redirect session | ClientKey: %s | CustomURL: %s | TunnelID: %s", clientKey, path, redirectSession.TunnelID)
			}

			// Always redirect to root for consistent SPA behavior
			redirectURL := "/"
			if r.URL.RawQuery != "" {
				redirectURL += "?" + r.URL.RawQuery
			}

			log.Printf("[REDIRECT EXECUTE] Always redirecting %s to %s for ClientKey: %s | CustomURL: %s", r.URL.Path, redirectURL, clientKey, path)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		} else if useRedirect {
			log.Printf("[REDIRECT SKIP] UseRedirect=%t but ForwardPath=%s (not '/'), skipping redirect logic | RequestURL: %s", useRedirect, forwardPath, r.URL.Path)
		}

		// Create modified request with new path
		newReq := r.Clone(r.Context())
		newReq.URL.Path = forwardPath
		log.Printf("[TUNNEL ROUTE] Attempting tunnel route | TunnelID: %s | OriginalPath: %s | ForwardPath: %s", tunnelID, r.URL.Path, forwardPath)

		if tryTunnelRouteWithTimeout(w, newReq, tunnelID, false) {
			// Record successful custom URL usage
			tunnelMetrics.RecordCustomURLRequest(path, "200")

			// Generate client key for affinity tracking
			clientKey := generateClientKey(r)

			// NEW: Set custom URL affinity for persistent routing
			clientIP := extractRealClientIP(r)
			affinityManager.SetAffinityWithIP(clientKey, tunnelID, path, "custom_url_visit", clientIP)

			// Create immediate tunnel binding for 2-second affinity window (legacy)
			clientTracker.CreateImmediateBinding(clientKey, tunnelID, "custom_url")

			log.Printf("[TUNNEL SUCCESS] Custom URL routing successful | CustomURL: %s | TunnelID: %s | ForwardPath: %s", path, tunnelID, forwardPath)
			return
		}

		// If tunnel failed, fall through to smart routing
		log.Printf("[TUNNEL FAILED] Custom URL routing failed | CustomURL: %s | TunnelID: %s | Falling back to smart routing", path, tunnelID)
	}

	// Try prefix matching for nested custom URLs (e.g., /bob/chatbot -> /bob)
	if strings.Contains(path, "/") {
		segments := strings.Split(path, "/")
		for i := len(segments) - 1; i > 0; i-- {
			parentPath := strings.Join(segments[:i], "/")

			customURLsMu.RLock()
			tunnelID := customURLs[parentPath]
			customURLsMu.RUnlock()

			if tunnelID != "" {
				log.Printf("Custom URL prefix routing: %s -> tunnel %s (prefix: %s)", r.URL.Path, tunnelID, parentPath)

				// Extract remaining path after the custom URL prefix
				remainingPath := "/" + strings.Join(segments[i:], "/")

				// Create modified request with remaining path
				newReq := r.Clone(r.Context())
				newReq.URL.Path = remainingPath

				if tryTunnelRouteWithTimeout(w, newReq, tunnelID, false) {
					// Record successful custom URL prefix usage
					tunnelMetrics.RecordCustomURLRequest(parentPath, "200")

					// Generate client key for affinity tracking
					clientKey := generateClientKey(r)

					// NEW: Set custom URL affinity for persistent routing
					clientIP := extractRealClientIP(r)
					affinityManager.SetAffinityWithIP(clientKey, tunnelID, parentPath, "custom_url_prefix", clientIP)

					// Create immediate tunnel binding for 2-second affinity window (legacy)
					clientTracker.CreateImmediateBinding(clientKey, tunnelID, "custom_url_prefix")

					return
				}

				log.Printf("Custom URL prefix routing: tunnel %s failed, falling back to smart routing", tunnelID)
				break
			}
		}
	}

	// No custom URL match found, fall back to smart routing
	log.Printf("[ROUTING FALLBACK] No custom URL match found | Path: %s | Falling back to smart routing", r.URL.Path)
	smartFallbackHandler(w, r)
}

// handleWebSocketUpgrade handles WebSocket upgrade requests from clients
func handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request, req *ReqFrame, ac *agentConn, reqID string) {
	// Step 1: Send WebSocket upgrade request to agent
	respCh := make(chan *RespFrame, 1)
	ac.registerWaiter(reqID, respCh)

	// Use no timeout for WebSocket connections (persistent)
	ctx := r.Context()

	// Send encrypted request to agent
	if err := ac.writeEncrypted(ctx, req); err != nil {
		tunnelMetrics.RecordError(ac.id, "websocket_write_failed")
		http.Error(w, "failed to write WebSocket upgrade to agent: "+err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("SERVER WEBSOCKET: Sent upgrade request to agent | ReqID: %s | AgentID: %s",
		reqID, ac.id)

	// Step 2: Wait for agent response
	select {
	case resp := <-respCh:
		if resp.Type != "websocket_upgrade_success" {
			log.Printf("SERVER WEBSOCKET: Agent upgrade failed | ReqID: %s | Status: %d",
				reqID, resp.Status)
			http.Error(w, "WebSocket upgrade failed at agent", http.StatusBadGateway)
			return
		}

		log.Printf("SERVER WEBSOCKET: Agent confirmed upgrade success | ReqID: %s", reqID)

		// Step 3: Upgrade client connection to WebSocket
		clientConn, err := upgradeClientToWebSocket(w, r)
		if err != nil {
			log.Printf("SERVER WEBSOCKET: Failed to upgrade client connection | ReqID: %s | Error: %v",
				reqID, err)
			return
		}

		log.Printf("SERVER WEBSOCKET: Client connection upgraded successfully | ReqID: %s", reqID)

		// Step 4: Create WebSocket session and start bidirectional forwarding
		session := &WebSocketSession{
			ReqID:      reqID,
			TunnelID:   ac.id,
			ClientConn: clientConn,
			ServerConn: ac,
			CreatedAt:  time.Now(),
			Active:     true,
		}

		// Register session
		webSocketMutex.Lock()
		webSocketSessions[reqID] = session
		webSocketMutex.Unlock()

		log.Printf("SERVER WEBSOCKET: Session created, starting bidirectional forwarding | ReqID: %s", reqID)

		// Step 5: Start bidirectional frame forwarding
		startWebSocketForwarding(session)

	case <-ctx.Done():
		log.Printf("SERVER WEBSOCKET: Client disconnected during upgrade | ReqID: %s", reqID)
		return
	}
}

// upgradeClientToWebSocket upgrades the HTTP connection to WebSocket
func upgradeClientToWebSocket(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	// Accept WebSocket connection from client
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,          // For development - should be configurable
		OriginPatterns:     []string{"*"}, // Allow all origins for now
	})
	if err != nil {
		return nil, fmt.Errorf("failed to accept WebSocket connection: %w", err)
	}

	return conn, nil
}

// startWebSocketForwarding handles bidirectional WebSocket frame forwarding
func startWebSocketForwarding(session *WebSocketSession) {
	// Start goroutine to forward frames from client to agent
	go func() {
		defer func() {
			// Cleanup session when client forwarding stops
			webSocketMutex.Lock()
			if session.Active {
				session.Active = false
				delete(webSocketSessions, session.ReqID)
			}
			webSocketMutex.Unlock()

			// Send close notification to agent
			closeFrame := WebSocketFrame{
				Type:      "websocket_close",
				ReqID:     session.ReqID,
				Direction: "to_agent",
			}
			session.ServerConn.writeEncrypted(context.Background(), closeFrame)

			log.Printf("SERVER WEBSOCKET: Client-to-agent forwarding stopped | ReqID: %s", session.ReqID)
		}()

		for session.Active {
			// Read frame from client
			msgType, data, err := session.ClientConn.Read(context.Background())
			if err != nil {
				closeStatus := websocket.CloseStatus(err)
				if closeStatus != websocket.StatusNormalClosure && closeStatus != websocket.StatusGoingAway {
					log.Printf("SERVER WEBSOCKET: Error reading from client | ReqID: %s | Error: %v",
						session.ReqID, err)
				}
				return
			}

			// Forward frame to agent
			frame := WebSocketFrame{
				Type:        "websocket_frame",
				ReqID:       session.ReqID,
				MessageType: int(msgType),
				Data:        data,
				Direction:   "to_agent",
			}

			if err := session.ServerConn.writeEncrypted(context.Background(), frame); err != nil {
				log.Printf("SERVER WEBSOCKET: Error forwarding frame to agent | ReqID: %s | Error: %v",
					session.ReqID, err)
				return
			}

			log.Printf("SERVER WEBSOCKET: Forwarded frame from client to agent | ReqID: %s | Type: %d | Size: %d bytes",
				session.ReqID, msgType, len(data))
		}
	}()

	log.Printf("SERVER WEBSOCKET: Bidirectional forwarding started | ReqID: %s | TunnelID: %s",
		session.ReqID, session.TunnelID)
}

// isProxyRequest detects if this is an HTTP proxy request
func isProxyRequest(r *http.Request) bool {
	// CONNECT method is used for HTTPS proxy tunneling
	if r.Method == "CONNECT" {
		return true
	}
	
	// Check for absolute URLs in regular HTTP proxy requests
	// Normal requests have relative paths, proxy requests have absolute URLs
	if r.URL.IsAbs() && r.URL.Host != "" && r.URL.Host != r.Host {
		return true
	}
	
	// Check for proxy-style Host header that differs from URL
	// This catches cases where URL was made relative but Host header remains absolute
	if r.Host != "" && !strings.Contains(r.Host, "vexorium.net") && 
	   !strings.Contains(r.Host, "localhost") && !strings.Contains(r.Host, "127.0.0.1") {
		return strings.Contains(r.Header.Get("User-Agent"), "curl") || 
			   strings.Contains(r.Header.Get("User-Agent"), "Chrome") ||
			   strings.Contains(r.Header.Get("User-Agent"), "Firefox")
	}
	
	return false
}

// proxyHandler handles HTTP proxy requests
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	log.Printf("[HTTP PROXY] Request: %s %s | Host: %s | Client IP: %s | User-Agent: %s", 
		r.Method, r.URL.String(), r.Host, r.RemoteAddr, r.Header.Get("User-Agent"))
	
	// Extract Proxy-Authorization credentials
	username, password, ok := parseProxyBasicAuth(r)
	if !ok {
		log.Printf("[HTTP PROXY] No proxy basic auth provided")
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Tunnel Proxy\"")
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}
	
	log.Printf("[HTTP PROXY] Basic auth: username=%s, password_len=%d", username, len(password))
	
	// Map username (custom URL) to tunnel ID
	customURLsMu.RLock()
	tunnelID := customURLs[username]
	customURLsMu.RUnlock()
	
	if tunnelID == "" {
		log.Printf("[HTTP PROXY] No tunnel found for custom URL: %s", username)
		http.Error(w, "Tunnel not found for provided credentials", http.StatusUnauthorized)
		return
	}
	
	// Get agent connection
	ac := getAgent(tunnelID)
	if ac == nil {
		log.Printf("[HTTP PROXY] Agent not connected for tunnel: %s", tunnelID)
		http.Error(w, "Tunnel agent not connected", http.StatusBadGateway)
		return
	}
	
	log.Printf("[HTTP PROXY] Found tunnel: %s for custom URL: %s", tunnelID, username)
	
	// Handle CONNECT method for HTTPS tunneling
	if r.Method == "CONNECT" {
		handleCONNECTProxy(w, r, ac, tunnelID, startTime)
		return
	}
	
	// Handle regular HTTP proxy request
	handleHTTPProxy(w, r, ac, tunnelID, startTime)
}

// handleHTTPProxy handles regular HTTP proxy requests (non-CONNECT)
func handleHTTPProxy(w http.ResponseWriter, r *http.Request, ac *agentConn, tunnelID string, startTime time.Time) {
	reqID := uuid.NewString()
	
	// Read request body
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	
	// Determine target URL
	var targetURL string
	if r.URL.IsAbs() {
		targetURL = r.URL.String()
	} else {
		// Reconstruct absolute URL from Host header
		scheme := "http"
		if r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			scheme = "https"
		}
		targetURL = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.RequestURI())
	}
	
	log.Printf("[HTTP PROXY] Proxying HTTP request: %s %s -> tunnel %s", r.Method, targetURL, tunnelID)
	
	// Create proxy request frame
	proxyReq := &ProxyReqFrame{
		Type:    "proxy_req",
		ReqID:   reqID,
		Method:  r.Method,
		URL:     targetURL,
		Headers: r.Header,
		Body:    body,
	}
	
	// Set up response channel
	respCh := make(chan *RespFrame, 1)
	ac.registerWaiter(reqID, respCh)
	
	// Send request to agent
	if err := ac.writeEncrypted(r.Context(), proxyReq); err != nil {
		log.Printf("[HTTP PROXY] Failed to send request to agent: %v", err)
		http.Error(w, "Failed to send request to tunnel", http.StatusBadGateway)
		return
	}
	
	// Wait for response with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	
	select {
	case resp := <-respCh:
		if resp.Type != "proxy_resp" {
			log.Printf("[HTTP PROXY] Unexpected response type: %s", resp.Type)
			http.Error(w, "Invalid response from tunnel", http.StatusBadGateway)
			return
		}
		
		// Forward response to client
		for k, vs := range resp.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		
		w.WriteHeader(resp.Status)
		w.Write(resp.Body)
		
		// Log metrics
		duration := time.Since(startTime).Seconds()
		log.Printf("[HTTP PROXY] Response: %d | Size: %d bytes | Duration: %.2fs | URL: %s", 
			resp.Status, len(resp.Body), duration, targetURL)
		
	case <-ctx.Done():
		log.Printf("[HTTP PROXY] Timeout waiting for response from tunnel %s", tunnelID)
		http.Error(w, "Timeout waiting for tunnel response", http.StatusGatewayTimeout)
	}
}

// handleCONNECTProxy handles CONNECT method for HTTPS tunneling
func handleCONNECTProxy(w http.ResponseWriter, r *http.Request, ac *agentConn, tunnelID string, startTime time.Time) {
	log.Printf("[HTTP PROXY] CONNECT method not yet implemented: %s", r.Host)
	http.Error(w, "CONNECT method not yet supported", http.StatusNotImplemented)
	// TODO: Implement CONNECT tunneling for HTTPS support
}

// parseProxyBasicAuth parses the Proxy-Authorization header for Basic authentication
func parseProxyBasicAuth(r *http.Request) (username, password string, ok bool) {
	proxyAuth := r.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return "", "", false
	}
	
	// Parse "Basic base64(username:password)"
	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return "", "", false
	}
	
	encoded := strings.TrimPrefix(proxyAuth, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	
	credentials := string(decoded)
	if colonIndex := strings.Index(credentials, ":"); colonIndex >= 0 {
		return credentials[:colonIndex], credentials[colonIndex+1:], true
	}
	
	// If no colon found, treat the whole string as username with empty password
	return credentials, "", true
}

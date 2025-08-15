package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// registerHandler handles agent registration requests
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request body for protocol and port info
	var req RegisterReq
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Default to HTTP if no body or invalid JSON (backward compatibility)
			req.Protocol = "http"
			req.Port = 0
		}
	}

	// Validate and set defaults
	if req.Protocol == "" {
		req.Protocol = "http"
	}
	if req.Protocol != "http" && req.Protocol != "tcp" {
		http.Error(w, "protocol must be 'http' or 'tcp'", http.StatusBadRequest)
		return
	}
	if req.Protocol == "tcp" && req.Port <= 0 {
		http.Error(w, "port is required for TCP tunnels", http.StatusBadRequest)
		return
	}

	// Validate custom URL if provided
	if err := validateCustomURL(req.CustomURL); err != nil {
		http.Error(w, fmt.Sprintf("invalid custom URL: %s", err.Error()), http.StatusBadRequest)
		return
	}

	// Check if custom URL is available
	if req.CustomURL != "" && !isCustomURLAvailable(req.CustomURL) {
		http.Error(w, "custom URL is already taken", http.StatusConflict)
		return
	}

	id := uuid.NewString()
	secret := randHex(32)

	// Normalize custom URL (remove leading/trailing slashes)
	var normalizedCustomURL string
	if req.CustomURL != "" {
		normalizedCustomURL = strings.Trim(req.CustomURL, "/")
	}

	tunnelInfo := &TunnelInfo{
		Secret:    secret,
		Protocol:  req.Protocol,
		Port:      req.Port,
		Created:   time.Now(),
		CustomURL: normalizedCustomURL,
	}

	// Register in memory (Cloud Run stateless)
	tunnelsMu.Lock()
	tunnels[id] = tunnelInfo
	tunnelsMu.Unlock()

	// Register custom URL mapping if provided
	if normalizedCustomURL != "" {
		customURLsMu.Lock()
		customURLs[normalizedCustomURL] = id
		customURLsMu.Unlock()
		log.Printf("Registered tunnel %s with custom URL: %s (stateless)", id, normalizedCustomURL)
	} else {
		log.Printf("Registered tunnel %s (stateless)", id)
	}

	publicBase := os.Getenv("PUBLIC_BASE_URL")
	if publicBase == "" {
		scheme := "https"
		host := r.Host
		if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
			scheme = "http"
		}
		publicBase = fmt.Sprintf("%s://%s", scheme, host)
	}

	var publicURL string
	var tcpPort int
	if req.Protocol == "tcp" {
		// For TCP tunnels, we'll create a different endpoint structure
		publicURL = fmt.Sprintf("%s/__tcp__/%s", publicBase, id)
		tcpPort = req.Port
	} else {
		// HTTP tunnels use the existing /__pub__/ endpoint
		publicURL = fmt.Sprintf("%s/__pub__/%s", publicBase, id)
	}

	// Build custom URL if provided
	var customURLResponse string
	if normalizedCustomURL != "" {
		customURLResponse = fmt.Sprintf("%s/%s", publicBase, normalizedCustomURL)
	}

	resp := RegisterResp{
		ID:        id,
		Secret:    secret,
		PublicURL: publicURL,
		CustomURL: customURLResponse,
		Protocol:  req.Protocol,
		TcpPort:   tcpPort,
	}
	writeJSON(w, http.StatusOK, resp)
}

// healthHandler provides server health and connection status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	agentsMu.RLock()
	defer agentsMu.RUnlock()

	type agentInfo struct {
		ID          string `json:"id"`
		ConnectedAt string `json:"connected_at"`
		Encrypted   bool   `json:"encrypted"`
	}

	info := struct {
		ActiveConnections   []agentInfo            `json:"active_connections"`
		ConnectionCount     int                    `json:"connection_count"`
		ClientTracking      map[string]interface{} `json:"client_tracking"`
		GeographicalRouting map[string]interface{} `json:"geographical_routing"`
		CustomURLs          map[string]interface{} `json:"custom_urls"`
	}{
		ActiveConnections:   make([]agentInfo, 0, len(agents)),
		ConnectionCount:     len(agents),
		ClientTracking:      clientTracker.GetClientStats(),
		GeographicalRouting: getGeoRoutingStats(),
		CustomURLs:          getCustomURLStats(),
	}

	for id, conn := range agents {
		info.ActiveConnections = append(info.ActiveConnections, agentInfo{
			ID:          id,
			ConnectedAt: conn.connectedAt.Format(time.RFC3339),
			Encrypted:   conn.cipher != nil,
		})
	}

	writeJSON(w, http.StatusOK, info)
}

// publicHandler handles public HTTP requests through tunnels
func publicHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "agent not connected", http.StatusBadGateway)
		return
	}

	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	reqID := uuid.NewString()
	req := &ReqFrame{
		Type:    "req",
		ReqID:   reqID,
		Method:  r.Method,
		Path:    restPath,
		Query:   r.URL.RawQuery,
		Headers: r.Header,
		Body:    body,
	}

	respCh := make(chan *RespFrame, 1)
	ac.registerWaiter(reqID, respCh)

	// Use longer timeout for potentially streaming responses
	timeout := 60 * time.Second
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") ||
		strings.Contains(r.Header.Get("Accept"), "text/stream") {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Send encrypted request
	if err := ac.writeEncrypted(ctx, req); err != nil {
		http.Error(w, "failed to write to agent: "+err.Error(), http.StatusBadGateway)
		return
	}

	select {
	case resp := <-respCh:
		// Record successful tunnel access for smart routing learning
		clientKey := generateClientKey(r)
		clientTracker.RecordSuccess(clientKey, id)

		// Record IP-based geographical routing
		clientIP := extractRealClientIP(r)
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
		if resp.Status == 0 {
			resp.Status = http.StatusOK
		}
		w.WriteHeader(resp.Status)
		_, _ = w.Write(resp.Body)
	case <-ctx.Done():
		http.Error(w, "timeout waiting agent", http.StatusGatewayTimeout)
	}
}

// customURLHandler handles custom URL routing with case-sensitive matching
func customURLHandler(w http.ResponseWriter, r *http.Request) {
	// Skip if this is already a system endpoint
	if strings.HasPrefix(r.URL.Path, "/__pub__/") ||
		strings.HasPrefix(r.URL.Path, "/__register__") ||
		strings.HasPrefix(r.URL.Path, "/__ws__") ||
		strings.HasPrefix(r.URL.Path, "/__tcp__/") ||
		strings.HasPrefix(r.URL.Path, "/__health__") {
		smartFallbackHandler(w, r)
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	
	// Try exact custom URL match first (case-sensitive)
	customURLsMu.RLock()
	tunnelID := customURLs[path]
	customURLsMu.RUnlock()
	
	if tunnelID != "" {
		log.Printf("Custom URL routing: %s -> tunnel %s", r.URL.Path, tunnelID)
		
		// Route to tunnel - the agent will receive request for "/"
		// For paths like /bob/chatbot/api/data, the agent gets /api/data
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
		
		// Create modified request with new path
		newReq := r.Clone(r.Context())
		newReq.URL.Path = forwardPath
		
		if tryTunnelRouteWithTimeout(w, newReq, tunnelID, false) {
			return
		}
		
		// If tunnel failed, fall through to smart routing
		log.Printf("Custom URL routing: tunnel %s failed, falling back to smart routing", tunnelID)
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
					return
				}
				
				log.Printf("Custom URL prefix routing: tunnel %s failed, falling back to smart routing", tunnelID)
				break
			}
		}
	}
	
	// No custom URL match found, fall back to smart routing
	smartFallbackHandler(w, r)
}
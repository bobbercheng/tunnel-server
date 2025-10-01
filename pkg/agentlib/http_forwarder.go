package agentlib

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// forward is the main HTTP forwarding method
func (a *Agent) forward(rd *ReqFrame) (int, map[string][]string, []byte, error) {
	return a.forwardInternal(rd, nil, nil)
}

// forwardWithStreamingHandler forwards requests with streaming support
func (a *Agent) forwardWithStreamingHandler(rd *ReqFrame, ctx context.Context, writeEncrypted func(v any) error) (int, map[string][]string, []byte, error) {
	return a.forwardInternal(rd, ctx, writeEncrypted)
}

// forwardInternal handles the core HTTP forwarding logic
func (a *Agent) forwardInternal(rd *ReqFrame, ctx context.Context, writeEncrypted func(v any) error) (int, map[string][]string, []byte, error) {
	target := a.LocalURL + rd.Path
	if rd.Query != "" {
		target += "?" + rd.Query
	}

	// Fix IPv6 localhost issue - force IPv4 localhost for better compatibility
	target = strings.Replace(target, "http://localhost:", "http://127.0.0.1:", 1)
	target = strings.Replace(target, "https://localhost:", "https://127.0.0.1:", 1)

	log.Printf("FORWARD: %s %s | ReqID: %s", rd.Method, target, rd.ReqID)

	req, err := http.NewRequest(rd.Method, target, bytes.NewReader(rd.Body))
	if err != nil {
		log.Printf("FORWARD ERROR: Failed to create HTTP request | Target: %s | ReqID: %s | Error: %v",
			target, rd.ReqID, err)
		return 0, nil, nil, err
	}
	for k, vs := range rd.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	// Determine if this is a localhost request
	isLocalhost := strings.Contains(target, "127.0.0.1") || strings.Contains(target, "localhost")

	// Create uTLS-enabled HTTP client for browser-like TLS fingerprinting
	client := createBrowserClientNew(isLocalhost)

	if isLocalhost {
		log.Printf("FORWARD: Using standard TLS for localhost | Target: %s | ReqID: %s", target, rd.ReqID)
	} else {
		log.Printf("FORWARD: Using uTLS browser fingerprint for external target | Target: %s | ReqID: %s", target, rd.ReqID)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("FORWARD ERROR: HTTP request failed | Target: %s | ReqID: %s | Error: %v",
			target, rd.ReqID, err)
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	log.Printf("FORWARD SUCCESS: Received response | Target: %s | ReqID: %s | Status: %d | ContentType: %s",
		target, rd.ReqID, resp.StatusCode, resp.Header.Get("Content-Type"))

	// DIAGNOSTIC: Log all headers for analysis
	log.Printf("FORWARD: All response headers | Target: %s | ReqID: %s | Headers: %+v",
		target, rd.ReqID, resp.Header)

	contentType := resp.Header.Get("Content-Type")

	// DIAGNOSTIC: Log streaming detection analysis
	isEventStream := strings.Contains(contentType, "text/event-stream")
	isTextStream := strings.Contains(contentType, "text/stream")
	isAppStream := strings.Contains(contentType, "application/stream")

	log.Printf("FORWARD: Streaming detection analysis | Target: %s | ReqID: %s | ContentType: '%s' | IsEventStream: %v | IsTextStream: %v | IsAppStream: %v",
		target, rd.ReqID, contentType, isEventStream, isTextStream, isAppStream)

	if isEventStream || isTextStream || isAppStream {
		log.Printf("FORWARD: Detected streaming response | Target: %s | ReqID: %s",
			target, rd.ReqID)

		// If we have streaming handler context, handle streaming directly here
		if ctx != nil && writeEncrypted != nil {
			log.Printf("FORWARD: Handling streaming response directly | Target: %s | ReqID: %s",
				target, rd.ReqID)
			a.handleStreamingResponseDirectNew(ctx, rd, resp, writeEncrypted)
			return resp.StatusCode, resp.Header, []byte("STREAMING_HANDLED"), nil
		}

		// Otherwise return indicator for legacy path
		return resp.StatusCode, resp.Header, []byte("STREAMING_RESPONSE"), nil
	}

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, 8*1024*1024) // 8MB limit
	b, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("FORWARD ERROR: Failed to read response body | Target: %s | ReqID: %s | Error: %v",
			target, rd.ReqID, err)
		return resp.StatusCode, resp.Header, nil, err
	}

	// Apply content rewriting for HTML/CSS/JS responses (if enabled)
	b = a.rewriteContent(b, contentType, rd)

	// Rewrite CORS and security headers (if enabled)
	a.rewriteResponseHeaders(resp.Header, rd)

	// Check if we hit the limit
	if len(b) == 8*1024*1024 {
		// Try to read one more byte to see if there's more data
		extra := make([]byte, 1)
		if n, _ := resp.Body.Read(extra); n > 0 {
			log.Printf("FORWARD ERROR: Response too large | Target: %s | ReqID: %s", target, rd.ReqID)
			return resp.StatusCode, resp.Header, nil, fmt.Errorf("response body too large (>8MB)")
		}
	}

	log.Printf("FORWARD COMPLETE: Request forwarded successfully | Target: %s | ReqID: %s | Status: %d | BodySize: %d",
		target, rd.ReqID, resp.StatusCode, len(b))
	return resp.StatusCode, resp.Header, b, nil
}

// handleStreamingResponse handles streaming responses (legacy function)
func handleStreamingResponse(resp *http.Response) (int, map[string][]string, []byte, error) {
	// DIAGNOSTIC: Log what we're returning for streaming responses
	log.Printf("handleStreamingResponse: Called for streaming response | Status: %d | ContentType: %s | Headers: %+v",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header)

	// For streaming responses, return the response object for reuse
	// We'll store it in a way that can be retrieved by the streaming handler
	return resp.StatusCode, resp.Header, []byte("STREAMING_RESPONSE"), nil
}

// handleHttpRequest processes incoming HTTP requests
func (a *Agent) handleHttpRequest(ctx context.Context, req *ReqFrame, writeEncrypted func(v any) error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Log all requests for debugging
		if a.DebugLog {
			a.logDebugRequestNew(req)
		}

		// Check if this is a WebSocket upgrade request
		if a.isWebSocketUpgradeNew(req) {
			log.Printf("AGENT: WebSocket upgrade detected | ReqID: %s", req.ReqID)
			a.handleWebSocketUpgradeNew(ctx, req, writeEncrypted)
			return
		}

		// Check for streaming request patterns
		isStreamingRequest := strings.Contains(req.Headers["Accept"][0], "text/event-stream") ||
			strings.Contains(req.Headers["Accept"][0], "text/stream") ||
			strings.Contains(req.Headers["Accept"][0], "application/stream") ||
			strings.Contains(req.Path, "/api/agents/") || // AI endpoints are likely streaming
			strings.Contains(req.Path, "/stream") ||
			strings.Contains(req.Path, "/chat")

		if isStreamingRequest {
			log.Printf("AGENT: Detected streaming request | ReqID: %s | Path: %s", req.ReqID, req.Path)
		}

		// Forward the request using enhanced streaming detection
		status, headers, body, err := a.forwardWithStreamingHandler(req, ctx, writeEncrypted)
		if err != nil {
			log.Printf("AGENT: Request forwarding failed, returning 502 Bad Gateway | ReqID: %s | TunnelID: %s | Error: %v", req.ReqID, a.ID, err)
			resp := RespFrame{
				Type:    "resp",
				ReqID:   req.ReqID,
				Status:  502,
				Headers: map[string][]string{"Content-Type": {"text/plain"}},
				Body:    []byte("Bad Gateway: " + err.Error()),
			}
			writeEncrypted(resp)
			return
		}

		// Check if this was handled as streaming
		if string(body) == "STREAMING_HANDLED" {
			log.Printf("AGENT: Streaming response handled directly | ReqID: %s", req.ReqID)
			return
		}

		// Check if this is a streaming response that needs legacy handling
		if string(body) == "STREAMING_RESPONSE" {
			log.Printf("AGENT: Legacy streaming response detected | ReqID: %s", req.ReqID)
			// TODO: Implement handleStreamingRequest method in streaming.go
			// a.handleStreamingRequest(ctx, req, status, headers, writeEncrypted)
			// For now, fall through to regular response handling
			return
		}

		// Regular response handling
		resp := RespFrame{
			Type:    "resp",
			ReqID:   req.ReqID,
			Status:  status,
			Headers: headers,
			Body:    body,
		}

		// Log all responses for debugging
		if a.DebugLog {
			a.logDebugResponseNew(&resp)
		}

		if err := writeEncrypted(resp); err != nil {
			log.Printf("AGENT: Failed to send response | ReqID: %s | Error: %v", req.ReqID, err)
		}
	}()
}

// handleProxyRequest handles HTTP proxy requests
func (a *Agent) handleProxyRequest(ctx context.Context, proxyReq *ProxyReqFrame, writeEncrypted func(v any) error) {
	log.Printf("AGENT PROXY: Processing HTTP proxy request | URL: %s | Method: %s | ReqID: %s",
		proxyReq.URL, proxyReq.Method, proxyReq.ReqID)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, proxyReq.Method, proxyReq.URL, bytes.NewReader(proxyReq.Body))
	if err != nil {
		log.Printf("AGENT PROXY: Failed to create request | URL: %s | ReqID: %s | Error: %v",
			proxyReq.URL, proxyReq.ReqID, err)
		// Send error response
		resp := ProxyRespFrame{
			Type:    "proxy_resp",
			ReqID:   proxyReq.ReqID,
			Status:  http.StatusBadRequest,
			Headers: map[string][]string{"Content-Type": {"text/plain"}},
			Body:    []byte("Invalid proxy request: " + err.Error()),
		}
		writeEncrypted(resp)
		return
	}

	// Add headers
	for k, vs := range proxyReq.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	// Determine if this is a localhost request for uTLS handling
	isLocalhost := strings.Contains(proxyReq.URL, "127.0.0.1") || strings.Contains(proxyReq.URL, "localhost")

	// Create browser client with uTLS for external requests
	client := createBrowserClientNew(isLocalhost)

	// Execute request
	httpResp, err := client.Do(req)
	if err != nil {
		log.Printf("AGENT PROXY: Request failed | URL: %s | ReqID: %s | Error: %v",
			proxyReq.URL, proxyReq.ReqID, err)
		// Send error response
		resp := ProxyRespFrame{
			Type:    "proxy_resp",
			ReqID:   proxyReq.ReqID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain"}},
			Body:    []byte("Proxy request failed: " + err.Error()),
		}
		writeEncrypted(resp)
		return
	}
	defer httpResp.Body.Close()

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		log.Printf("AGENT PROXY: Failed to read response body | URL: %s | ReqID: %s | Error: %v",
			proxyReq.URL, proxyReq.ReqID, err)
		// Send error response
		resp := ProxyRespFrame{
			Type:    "proxy_resp",
			ReqID:   proxyReq.ReqID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain"}},
			Body:    []byte("Failed to read response: " + err.Error()),
		}
		writeEncrypted(resp)
		return
	}

	log.Printf("AGENT PROXY: Request successful | URL: %s | ReqID: %s | Status: %d | BodySize: %d",
		proxyReq.URL, proxyReq.ReqID, httpResp.StatusCode, len(body))

	// Send successful response
	resp := ProxyRespFrame{
		Type:    "proxy_resp",
		ReqID:   proxyReq.ReqID,
		Status:  httpResp.StatusCode,
		Headers: httpResp.Header,
		Body:    body,
	}

	if err := writeEncrypted(resp); err != nil {
		log.Printf("AGENT PROXY: Failed to send response | ReqID: %s | Error: %v", proxyReq.ReqID, err)
	}
}

// forwardHTTPRequestNew handles HTTP request forwarding (main delegation function called from connection.go)
func (a *Agent) forwardHTTPRequestNew(req *ReqFrame, writeEncrypted func(v any) error) {
	// Use the existing handleHttpRequest method which has the full implementation
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.handleHttpRequest(ctx, req, writeEncrypted, &wg)
	}()
	wg.Wait()
}
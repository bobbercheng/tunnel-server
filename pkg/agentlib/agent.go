package agentlib

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// WebSocketFrame is used for WebSocket frame forwarding
type WebSocketFrame struct {
	Type        string `json:"type"`         // "websocket_frame" or "websocket_close"
	ReqID       string `json:"req_id"`       // request identifier
	MessageType int    `json:"message_type"` // WebSocket message type (text, binary, etc.)
	Data        []byte `json:"data"`         // frame data
	Direction   string `json:"direction"`    // "to_server" or "to_client"
}

type RegisterResp struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	PublicURL   string `json:"public_url"`
	CustomURL   string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol    string `json:"protocol"`
	TcpPort     int    `json:"tcp_port,omitempty"`     // for TCP tunnels
	UseRedirect bool   `json:"use_redirect,omitempty"` // redirection enabled
}

type ReqFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type RespFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type ChunkedRespFrame struct {
	Type        string              `json:"type"` // "chunked_resp"
	ReqID       string              `json:"req_id"`
	Status      int                 `json:"status"`
	Headers     map[string][]string `json:"headers"`
	ChunkIndex  int                 `json:"chunk_index"`
	TotalChunks int                 `json:"total_chunks"`
	Data        []byte              `json:"data"`
	IsLast      bool                `json:"is_last"`
}

// HandshakeFrame is used for initial key exchange
type HandshakeFrame struct {
	Type string `json:"type"` // "handshake"
	Salt string `json:"salt"` // base64 encoded salt
}

// RegisterFrame is used for agent registration over WebSocket (encrypted)
type RegisterFrame struct {
	Type        string `json:"type"`                   // "register"
	Protocol    string `json:"protocol"`               // "http" or "tcp"
	Port        int    `json:"port"`                   // for TCP tunnels, the local port being tunneled
	CustomURL   string `json:"custom_url,omitempty"`   // custom URL like "bob/chatbot"
	UseRedirect bool   `json:"use_redirect,omitempty"` // enable SPA redirection
}

// RegisterResponseFrame is the server's response to registration (encrypted)
type RegisterResponseFrame struct {
	Type        string `json:"type"` // "register_response"
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	PublicURL   string `json:"public_url"`           // Default /__pub__/{id} or /__tcp__/{id}
	CustomURL   string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol    string `json:"protocol"`
	TcpPort     int    `json:"tcp_port,omitempty"`     // for TCP tunnels
	UseRedirect bool   `json:"use_redirect,omitempty"` // redirection enabled
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"` // error message if Success is false
}

// TCP Frame types for raw TCP tunneling
type TcpConnectFrame struct {
	Type   string `json:"type"`    // "tcp_connect"
	ConnID string `json:"conn_id"` // unique connection identifier
	Port   int    `json:"port"`    // destination port
}

type TcpDataFrame struct {
	Type   string `json:"type"`    // "tcp_data"
	ConnID string `json:"conn_id"` // connection identifier
	Data   []byte `json:"data"`    // raw TCP data
}

type TcpDisconnectFrame struct {
	Type   string `json:"type"`    // "tcp_disconnect"
	ConnID string `json:"conn_id"` // connection identifier
	Reason string `json:"reason"`  // disconnect reason
}

// Ping/Pong frames for connection health monitoring
type PingFrame struct {
	Type      string    `json:"type"`      // "ping"
	Timestamp time.Time `json:"timestamp"` // when ping was sent
	TunnelID  string    `json:"tunnel_id"` // tunnel identifier
}

type PongFrame struct {
	Type      string    `json:"type"`      // "pong"
	Timestamp time.Time `json:"timestamp"` // original ping timestamp
	TunnelID  string    `json:"tunnel_id"` // tunnel identifier (echoed from ping)
}

// TunnelInfoFrame is sent by agent to provide tunnel details during reconnection
type TunnelInfoFrame struct {
	Type     string `json:"type"`     // "tunnel_info"
	Protocol string `json:"protocol"` // "http" or "tcp"
	Port     int    `json:"port"`     // for TCP tunnels
}

var (
	ErrUnauthorized   = errors.New("unauthorized: credentials rejected by server")
	ErrNetworkFailure = errors.New("network failure: unable to reach server")
	ErrDNSFailure     = errors.New("dns failure: unable to resolve server hostname")
	ErrTunnelMismatch = errors.New("tunnel mismatch: server expects different tunnel ID")
)

type Agent struct {
	ServerURL   string
	LocalURL    string
	ID          string
	Secret      string
	Protocol    string // "http" or "tcp"
	Port        int    // for TCP tunnels
	CustomURL   string // custom URL for this tunnel
	UseRedirect bool   // enable SPA redirection

	// Retry state
	consecutiveDNSFailures     int
	consecutiveNetworkFailures int

	// TCP connection management
	tcpConnsMu sync.Mutex
	tcpConns   map[string]net.Conn // connID -> TCP connection

	// Chunked response management
	chunkedRespMu sync.Mutex
	chunkedResps  map[string]*ChunkedResponse // reqID -> partial response

	// Connection health monitoring
	lastPong time.Time
	pingMu   sync.RWMutex
}

// ChunkedResponse tracks partial chunked responses
type ChunkedResponse struct {
	Status         int
	Headers        map[string][]string
	Chunks         map[int][]byte // chunkIndex -> data
	TotalChunks    int
	ReceivedChunks int
}

func (a *Agent) Run() {
	// Note: Registration now happens over WebSocket during connection

	for {
		err := a.runOnce()
		if err == nil {
			// Reset failure counters on successful connection
			a.consecutiveDNSFailures = 0
			a.consecutiveNetworkFailures = 0
			fmt.Println("Connection closed normally. Reconnecting in 2 seconds...")
			time.Sleep(2 * time.Second)
			continue
		}

		if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrTunnelMismatch) {
			if errors.Is(err, ErrUnauthorized) {
				log.Println("REREGISTRATION: Credentials rejected by server, re-registering for a new tunnel...")
			} else {
				log.Println("REREGISTRATION: Tunnel ID mismatch detected (server restarted), re-registering for a new tunnel...")
			}

			log.Printf("REREGISTRATION: Previous tunnel ID: %s", a.ID)
			reg, regErr := a.register()
			if regErr != nil {
				log.Printf("REREGISTRATION: Failed to re-register: %v", regErr)
				log.Println("REREGISTRATION: Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			}
			// Update only ID and Secret from server response
			// Keep original configuration (CustomURL, UseRedirect, etc.) to avoid
			// sending back server-formatted URLs that fail validation
			previousID := a.ID
			a.ID = reg.ID
			a.Secret = reg.Secret
			// Reset failure counters after successful re-registration
			a.consecutiveDNSFailures = 0
			a.consecutiveNetworkFailures = 0
			log.Println("REREGISTRATION: Re-registered successfully!")
			log.Printf("  Previous ID: %s", previousID)
			log.Printf("  New ID: %s", a.ID)
			log.Printf("  New Secret: %s", maskSecret(a.Secret))
			log.Printf("  New Public URL: %s", reg.PublicURL)
			if a.CustomURL != "" {
				log.Printf("  Custom URL: %s", a.CustomURL)
				if a.UseRedirect {
					log.Println("  SPA Redirection: Enabled")
				}
			}
			continue
		}

		if errors.Is(err, ErrDNSFailure) {
			a.consecutiveDNSFailures++
			a.consecutiveNetworkFailures = 0 // Reset network failure count
			delay := calculateBackoff(a.consecutiveDNSFailures, 5*time.Second, 60*time.Second)
			fmt.Printf("DNS resolution failed (attempt %d): %v\n", a.consecutiveDNSFailures, err)
			fmt.Printf("Retrying in %v... (keeping existing tunnel)\n", delay)
			time.Sleep(delay)
			continue
		}

		if errors.Is(err, ErrNetworkFailure) {
			a.consecutiveNetworkFailures++
			a.consecutiveDNSFailures = 0 // Reset DNS failure count
			delay := calculateBackoff(a.consecutiveNetworkFailures, 3*time.Second, 30*time.Second)
			fmt.Printf("Network connection failed (attempt %d): %v\n", a.consecutiveNetworkFailures, err)
			fmt.Printf("Retrying in %v... (keeping existing tunnel)\n", delay)
			time.Sleep(delay)
			continue
		}

		fmt.Printf("Connection error: %v\n", err)
		fmt.Println("Reconnecting in 2 seconds...")
		time.Sleep(2 * time.Second)
	}
}

func (a *Agent) runOnce() error {
	// Initialize TCP connections map
	a.tcpConnsMu.Lock()
	if a.tcpConns == nil {
		a.tcpConns = make(map[string]net.Conn)
	}
	a.tcpConnsMu.Unlock()

	// Initialize chunked response map
	a.chunkedRespMu.Lock()
	if a.chunkedResps == nil {
		a.chunkedResps = make(map[string]*ChunkedResponse)
	}
	a.chunkedRespMu.Unlock()

	dialCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var wsURL string
	if a.ID != "" && a.Secret != "" {
		// Reconnection with existing credentials
		wsURL = fmt.Sprintf("%s/__ws__?id=%s&secret=%s", a.ServerURL, url.QueryEscape(a.ID), url.QueryEscape(a.Secret))
	} else {
		// New connection - no credentials yet
		wsURL = fmt.Sprintf("%s/__ws__", a.ServerURL)
	}

	// Configure WebSocket options with larger message size limit
	ws, resp, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	})
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return ErrUnauthorized
			}
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("handshake failed with status %d: %s", resp.StatusCode, string(body))
		}
		// Classify network errors to avoid unnecessary re-registration
		return classifyNetworkError(err)
	}
	defer ws.Close(websocket.StatusInternalError, "internal error")

	// Set larger message size limit (20MB to match server)
	ws.SetReadLimit(20 * 1024 * 1024)

	// Perform key exchange
	ctx := context.Background()

	// Read handshake from server
	_, data, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read handshake: %w", err)
	}

	var handshake HandshakeFrame
	if err := json.Unmarshal(data, &handshake); err != nil {
		return fmt.Errorf("invalid handshake format: %w", err)
	}

	if handshake.Type != "handshake" {
		return fmt.Errorf("expected handshake message, got: %s", handshake.Type)
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		return fmt.Errorf("invalid salt in handshake: %w", err)
	}

	// Create cipher - for new connections we'll use a well-known temporary secret, for reconnections we use the stored secret
	var secretForHandshake string
	if a.Secret != "" {
		secretForHandshake = a.Secret
	} else {
		// For new connections, use a well-known temporary secret that the server will also use
		secretForHandshake = "temp_handshake_secret_for_registration"
	}

	masterSecret := sha256Sum([]byte(secretForHandshake))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false) // false = isClient
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Send handshake ACK
	handshakeResp := struct {
		Type string `json:"type"`
		ACK  bool   `json:"ack"`
	}{
		Type: "handshake",
		ACK:  true,
	}
	if err := ws.Write(ctx, websocket.MessageText, mustJSON(handshakeResp)); err != nil {
		return fmt.Errorf("failed to send handshake ACK: %w", err)
	}

	log.Printf("Connection established successfully with encryption (tunnel_id: %s)", a.ID)

	// If this is a new connection (no ID/Secret), perform registration over encrypted WebSocket
	if a.ID == "" || a.Secret == "" {
		log.Println("No tunnel id/secret provided, registering new tunnel...")
		err := a.registerOverWebSocket(ctx, ws, cipher)
		if err != nil {
			return fmt.Errorf("WebSocket registration failed: %w", err)
		}
		log.Println("Registered successfully!")
		log.Printf("  Tunnel ID: %s", a.ID)
		log.Printf("  Secret: %s", maskSecret(a.Secret))
		// Note: Public URL and Custom URL will be logged by registerOverWebSocket
	} else {
		log.Printf("Reconnecting with existing tunnel (ID: %s, Secret: %s)", a.ID, maskSecret(a.Secret))
	}

	// Log agent configuration for debugging
	log.Printf("AGENT CONFIG: LocalURL: %s | Protocol: %s | CustomURL: %s | UseRedirect: %v | Port: %d",
		a.LocalURL, a.Protocol, a.CustomURL, a.UseRedirect, a.Port)

	// Create a context that will be cancelled when the connection closes
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// Track active request handlers
	var wg sync.WaitGroup

	// Mutex to protect websocket writes
	var writeMu sync.Mutex

	// Channel to signal connection closure
	done := make(chan struct{})

	// Channel to communicate specific errors
	errChan := make(chan error, 1)

	// Helper function to write encrypted messages
	writeEncrypted := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()

		// Marshal to JSON
		jsonData := mustJSON(v)

		// Encrypt the data
		encryptedData, err := cipher.Encrypt(jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}

		// Send as binary WebSocket message
		return ws.Write(ctx, websocket.MessageBinary, encryptedData)
	}

	// Send tunnel info for stateless server reconnection (Cloud Run)
	tunnelInfo := TunnelInfoFrame{
		Type:     "tunnel_info",
		Protocol: a.Protocol,
		Port:     a.Port,
	}
	if err := writeEncrypted(tunnelInfo); err != nil {
		log.Printf("Failed to send tunnel info: %v", err)
		// Don't fail connection for this
	} else {
		log.Printf("Sent tunnel info: protocol=%s, port=%d", a.Protocol, a.Port)
	}

	// Initialize ping monitoring
	a.pingMu.Lock()
	a.lastPong = time.Now()
	a.pingMu.Unlock()

	// Start ping monitoring goroutine with more aggressive timeouts for Cloud Run
	go func() {
		ticker := time.NewTicker(15 * time.Second) // Ping every 15 seconds for faster detection
		defer ticker.Stop()

		consecutiveMissedPongs := 0
		maxMissedPongs := 4 // Allow 4 missed pongs (60 seconds total) before considering connection dead

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Send ping with tunnel ID
				pingFrame := PingFrame{
					Type:      "ping",
					Timestamp: time.Now(),
					TunnelID:  a.ID,
				}

				if err := writeEncrypted(pingFrame); err != nil {
					log.Printf("Failed to send ping: %v", err)
					cancelCtx()
					return
				}

				// Check if last pong is too old with more aggressive timeout for Cloud Run
				a.pingMu.RLock()
				lastPong := a.lastPong
				a.pingMu.RUnlock()

				timeSinceLastPong := time.Since(lastPong)

				// More aggressive timeout: 75 seconds (5 pings * 15 seconds)
				if timeSinceLastPong > 75*time.Second {
					consecutiveMissedPongs++
					log.Printf("Missed pong #%d (last pong: %v ago)", consecutiveMissedPongs, timeSinceLastPong)

					if consecutiveMissedPongs >= maxMissedPongs {
						log.Printf("Connection appears to be dead (no pong received for %v, %d consecutive misses), closing...", timeSinceLastPong, consecutiveMissedPongs)
						cancelCtx()
						return
					}
				} else {
					// Reset counter if we received a recent pong
					if consecutiveMissedPongs > 0 {
						log.Printf("Connection recovered, resetting missed pong counter (was %d)", consecutiveMissedPongs)
						consecutiveMissedPongs = 0
					}
				}
			}
		}
	}()

	// Start additional connection health monitoring goroutine
	go func() {
		healthTicker := time.NewTicker(10 * time.Second) // Check connection health every 10 seconds
		defer healthTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				// Try to ping the WebSocket connection itself (not application-level ping)
				pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
				err := ws.Ping(pingCtx)
				pingCancel()

				if err != nil {
					log.Printf("WebSocket ping failed, connection appears broken: %v", err)
					cancelCtx()
					return
				}
			}
		}
	}()

	// Start a goroutine to read messages
	go func() {
		defer close(done)
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				// Log specific error details for debugging
				log.Printf("WebSocket read error: %v", err)
				// Connection closed, cancel context to stop all handlers
				cancelCtx()
				return
			}
			if typ != websocket.MessageBinary {
				continue
			}

			// Decrypt the message
			plaintext, err := cipher.Decrypt(data)
			if err != nil {
				fmt.Printf("Failed to decrypt message: %v\n", err)
				continue
			}

			var base struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(plaintext, &base); err != nil {
				continue
			}

			switch base.Type {
			case "req":
				var req ReqFrame
				if err := json.Unmarshal(plaintext, &req); err != nil {
					log.Printf("AGENT: Failed to parse HTTP request: %v", err)
					continue
				}
				log.Printf("AGENT: %s %s | ReqID: %s", req.Method, req.Path, req.ReqID)
				a.handleHttpRequest(ctx, &req, writeEncrypted, &wg)
			case "chunked_resp":
				var chunk ChunkedRespFrame
				if err := json.Unmarshal(plaintext, &chunk); err != nil {
					continue
				}
				go a.handleChunkedResponse(&chunk, writeEncrypted)
			case "tcp_connect":
				var frame TcpConnectFrame
				if err := json.Unmarshal(plaintext, &frame); err != nil {
					continue
				}
				go a.handleTcpConnect(ctx, &frame, writeEncrypted)
			case "tcp_data":
				var frame TcpDataFrame
				if err := json.Unmarshal(plaintext, &frame); err != nil {
					continue
				}
				go a.handleTcpData(&frame)
			case "tcp_disconnect":
				var frame TcpDisconnectFrame
				if err := json.Unmarshal(plaintext, &frame); err != nil {
					continue
				}
				go a.handleTcpDisconnect(&frame)
			case "websocket_frame":
				var frame WebSocketFrame
				if err := json.Unmarshal(plaintext, &frame); err != nil {
					log.Printf("AGENT: Failed to parse WebSocket frame: %v", err)
					continue
				}
				go a.handleWebSocketFrame(&frame)
			case "websocket_close":
				var frame WebSocketFrame
				if err := json.Unmarshal(plaintext, &frame); err != nil {
					log.Printf("AGENT: Failed to parse WebSocket close: %v", err)
					continue
				}
				go a.handleWebSocketClose(&frame)
			case "ping":
				// Respond to server ping with pong
				var pingFrame PingFrame
				if err := json.Unmarshal(plaintext, &pingFrame); err != nil {
					continue
				}

				// Check if server's expected tunnel ID matches ours
				if pingFrame.TunnelID != a.ID {
					log.Printf("TUNNEL MISMATCH: Received ping with mismatched tunnel ID")
					log.Printf("  Agent tunnel ID: %s", a.ID)
					log.Printf("  Server tunnel ID: %s", pingFrame.TunnelID)
					log.Printf("  This indicates server restarted or lost tunnel state")
					log.Printf("  Triggering re-registration...")
					// Send tunnel mismatch error
					select {
					case errChan <- ErrTunnelMismatch:
					default:
					}
					// Close the connection to trigger re-registration
					cancelCtx()
					return
				}

				// Echo back the tunnel ID from the ping
				pongFrame := PongFrame{
					Type:      "pong",
					Timestamp: pingFrame.Timestamp,
					TunnelID:  pingFrame.TunnelID,
				}
				if err := writeEncrypted(pongFrame); err != nil {
					log.Printf("Failed to send pong: %v", err)
				}
			case "pong":
				// Handle pong response from server
				var pongFrame PongFrame
				if err := json.Unmarshal(plaintext, &pongFrame); err != nil {
					log.Printf("Failed to parse pong: %v", err)
					continue
				}

				// Validate tunnel ID matches
				if pongFrame.TunnelID != a.ID {
					log.Printf("TUNNEL MISMATCH: Received pong with mismatched tunnel ID")
					log.Printf("  Agent tunnel ID: %s", a.ID)
					log.Printf("  Server tunnel ID: %s", pongFrame.TunnelID)
					log.Printf("  This indicates server restarted or lost tunnel state")
					log.Printf("  Triggering re-registration...")
					// Send tunnel mismatch error
					select {
					case errChan <- ErrTunnelMismatch:
					default:
					}
					// Close the connection to trigger re-registration
					cancelCtx()
					return
				}

				// Update last pong time for connection health monitoring
				a.pingMu.Lock()
				previousPongTime := a.lastPong
				a.lastPong = time.Now()
				a.pingMu.Unlock()

				// Log pong received for debugging (only log occasionally to avoid spam)
				if time.Since(previousPongTime) > 30*time.Second {
					log.Printf("Received pong from server (tunnel_id: %s, latency: %v)",
						pongFrame.TunnelID, time.Since(pongFrame.Timestamp))
				}
			default:
				continue
			}
		}
	}()

	// Wait for connection to close
	<-done

	// Cancel context to stop all handlers
	cancelCtx()

	// Check if there was a specific error
	var returnErr error
	select {
	case err := <-errChan:
		returnErr = err
	default:
		// No specific error
	}

	// Wait for all request handlers to finish with a timeout
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// All handlers finished gracefully
	case <-time.After(5 * time.Second):
		// Timeout waiting for handlers
		fmt.Println("Warning: some request handlers did not finish in time")
	}

	return returnErr
}

func (a *Agent) forward(rd *ReqFrame) (int, map[string][]string, []byte, error) {
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

	// Create HTTP client that forces IPv4 for localhost connections
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Force IPv4 for localhost connections to avoid IPv6 issues
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return net.DialTimeout("tcp4", addr, 10*time.Second)
				}
				return net.DialTimeout(network, addr, 10*time.Second)
			},
		},
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
		log.Printf("FORWARD: Detected streaming response, calling handleStreamingResponse | Target: %s | ReqID: %s",
			target, rd.ReqID)
		return handleStreamingResponse(resp)
	}

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, 8*1024*1024) // 8MB limit
	b, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("FORWARD ERROR: Failed to read response body | Target: %s | ReqID: %s | Error: %v",
			target, rd.ReqID, err)
		return resp.StatusCode, resp.Header, nil, err
	}

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

func handleStreamingResponse(resp *http.Response) (int, map[string][]string, []byte, error) {
	// DIAGNOSTIC: Log what we're returning for streaming responses
	log.Printf("handleStreamingResponse: Called for streaming response | Status: %d | ContentType: %s | Headers: %+v",
		resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header)

	// For streaming responses, return an indicator that streaming is in progress
	// The actual streaming will be handled by the caller
	return resp.StatusCode, resp.Header, []byte("STREAMING_RESPONSE"), nil
}

// handleStreamingRequest handles real-time streaming responses (SSE, etc.)
func (a *Agent) handleStreamingRequest(ctx context.Context, req *ReqFrame, status int, headers map[string][]string, writeEncrypted func(v any) error) {
	// Make a new HTTP request to get the actual response stream
	target := a.LocalURL + req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	// Fix IPv6 localhost issue - force IPv4 localhost for better compatibility
	target = strings.Replace(target, "http://localhost:", "http://127.0.0.1:", 1)
	target = strings.Replace(target, "https://localhost:", "https://127.0.0.1:", 1)

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, target, bytes.NewReader(req.Body))
	if err != nil {
		log.Printf("AGENT STREAMING: Failed to create HTTP request | Target: %s | ReqID: %s | Error: %v",
			target, req.ReqID, err)
		return
	}

	// Copy headers
	for k, vs := range req.Headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 0, // No timeout for streaming responses
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Force IPv4 for localhost connections to avoid IPv6 issues
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return net.DialTimeout("tcp4", addr, 10*time.Second)
				}
				return net.DialTimeout(network, addr, 10*time.Second)
			},
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("AGENT STREAMING: HTTP request failed | Target: %s | ReqID: %s | Error: %v",
			target, req.ReqID, err)
		return
	}
	defer resp.Body.Close()

	log.Printf("AGENT STREAMING: Stream established | ReqID: %s | Status: %d | ContentType: %s",
		req.ReqID, resp.StatusCode, resp.Header.Get("Content-Type"))

	// DIAGNOSTIC: Log all headers received from local service
	log.Printf("AGENT STREAMING: All headers from local service | ReqID: %s | Headers: %+v", req.ReqID, resp.Header)

	// DIAGNOSTIC: Check if content-type is what we expect for streaming
	contentType := resp.Header.Get("Content-Type")
	log.Printf("AGENT STREAMING: Content-Type analysis | ReqID: %s | ContentType: '%s' | IsEventStream: %v | IsStream: %v",
		req.ReqID, contentType,
		strings.Contains(contentType, "text/event-stream"),
		strings.Contains(contentType, "text/stream") || strings.Contains(contentType, "application/stream"))

	// Send streaming start message with headers and status
	startFrame := ChunkedRespFrame{
		Type:        "streaming_start",
		ReqID:       req.ReqID,
		Status:      resp.StatusCode,
		Headers:     resp.Header,
		ChunkIndex:  0,
		TotalChunks: -1, // Unknown for streaming
		Data:        []byte{},
		IsLast:      false,
	}

	// DIAGNOSTIC: Log what we're sending in the streaming_start frame
	log.Printf("AGENT STREAMING: Sending streaming_start frame | ReqID: %s | Headers: %+v", req.ReqID, startFrame.Headers)

	if err := writeEncrypted(startFrame); err != nil {
		log.Printf("AGENT STREAMING: Failed to send streaming_start | ReqID: %s | Error: %v", req.ReqID, err)
		return
	}

	// Stream data in real-time
	buf := make([]byte, 4096)
	chunkIndex := 1

	for {
		select {
		case <-ctx.Done():
			log.Printf("AGENT STREAMING: Context cancelled | ReqID: %s", req.ReqID)
			return
		default:
			n, err := resp.Body.Read(buf)
			if n > 0 {
				// Send chunk immediately
				chunkFrame := ChunkedRespFrame{
					Type:        "streaming_chunk",
					ReqID:       req.ReqID,
					Status:      resp.StatusCode,
					Headers:     nil, // Headers only sent in start frame
					ChunkIndex:  chunkIndex,
					TotalChunks: -1, // Unknown for streaming
					Data:        make([]byte, n),
					IsLast:      false,
				}
				copy(chunkFrame.Data, buf[:n])

				if err := writeEncrypted(chunkFrame); err != nil {
					log.Printf("AGENT STREAMING: Failed to send chunk %d | ReqID: %s | Error: %v", chunkIndex, req.ReqID, err)
					return
				}

				log.Printf("AGENT STREAMING: Sent chunk %d (%d bytes) | ReqID: %s", chunkIndex, n, req.ReqID)
				chunkIndex++
			}

			if err != nil {
				if err == io.EOF {
					// Stream ended normally
					endFrame := ChunkedRespFrame{
						Type:        "streaming_end",
						ReqID:       req.ReqID,
						Status:      resp.StatusCode,
						Headers:     nil,
						ChunkIndex:  chunkIndex,
						TotalChunks: chunkIndex,
						Data:        []byte{},
						IsLast:      true,
					}

					if err := writeEncrypted(endFrame); err != nil {
						log.Printf("AGENT STREAMING: Failed to send streaming_end | ReqID: %s | Error: %v", req.ReqID, err)
					} else {
						log.Printf("AGENT STREAMING: Stream completed successfully | ReqID: %s | TotalChunks: %d", req.ReqID, chunkIndex)
					}
					return
				} else {
					// Stream error
					log.Printf("AGENT STREAMING: Stream read error | ReqID: %s | Error: %v", req.ReqID, err)
					return
				}
			}
		}
	}
}

// registerOverWebSocket performs registration over encrypted WebSocket connection
func (a *Agent) registerOverWebSocket(ctx context.Context, ws *websocket.Conn, cipher *crypto.StreamCipher) error {
	// Create registration frame
	regFrame := &RegisterFrame{
		Type:        "register",
		Protocol:    a.Protocol,
		Port:        a.Port,
		CustomURL:   a.CustomURL,
		UseRedirect: a.UseRedirect,
	}

	// Default to HTTP if not specified
	if regFrame.Protocol == "" {
		regFrame.Protocol = "http"
	}

	// Encrypt and send registration request
	regData, err := json.Marshal(regFrame)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	encryptedRegData, err := cipher.Encrypt(regData)
	if err != nil {
		return fmt.Errorf("failed to encrypt registration: %w", err)
	}

	if err := ws.Write(ctx, websocket.MessageBinary, encryptedRegData); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration response
	_, responseData, err := ws.Read(ctx)
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	// Decrypt response
	decryptedResponse, err := cipher.Decrypt(responseData)
	if err != nil {
		return fmt.Errorf("failed to decrypt registration response: %w", err)
	}

	var regResp RegisterResponseFrame
	if err := json.Unmarshal(decryptedResponse, &regResp); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	if regResp.Type != "register_response" {
		return fmt.Errorf("unexpected response type: %s", regResp.Type)
	}

	if !regResp.Success {
		return fmt.Errorf("registration failed: %s", regResp.Error)
	}

	// Store only ID and Secret from server response
	// Agent configuration (CustomURL, UseRedirect, Protocol, Port) should remain
	// as originally provided to avoid sending back server-formatted values
	a.ID = regResp.ID
	a.Secret = regResp.Secret

	// Log the URLs from server response
	fmt.Println("  Public URL:", regResp.PublicURL)
	if regResp.CustomURL != "" {
		fmt.Println("  Custom URL:", regResp.CustomURL)
		if regResp.UseRedirect {
			fmt.Println("  SPA Redirection: Enabled")
		}
	}

	return nil
}

func (a *Agent) register() (*RegisterResp, error) {
	// Create WebSocket connection for registration (without existing credentials)
	wsURL := strings.Replace(a.ServerURL, "http", "ws", 1) + "/__ws__"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for registration: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "registration complete")

	// Complete handshake first
	var handshake HandshakeFrame
	err = wsjson.Read(ctx, conn, &handshake)
	if err != nil {
		return nil, fmt.Errorf("failed to read handshake: %w", err)
	}

	// Send handshake ACK
	handshakeResp := map[string]interface{}{
		"type": "handshake",
		"ack":  true,
	}
	err = wsjson.Write(ctx, conn, handshakeResp)
	if err != nil {
		return nil, fmt.Errorf("failed to send handshake ACK: %w", err)
	}

	// Create cipher for registration
	salt, err := base64.StdEncoding.DecodeString(handshake.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Use the well-known temporary secret that the server expects for new registrations
	tempSecretString := "temp_handshake_secret_for_registration"
	masterSecret := sha256.Sum256([]byte(tempSecretString))
	cipher, err := crypto.NewStreamCipher(masterSecret[:], salt, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create registration frame
	regFrame := &RegisterFrame{
		Type:        "register",
		Protocol:    a.Protocol,
		Port:        a.Port,
		CustomURL:   a.CustomURL,
		UseRedirect: a.UseRedirect,
	}

	// Default to HTTP if not specified
	if regFrame.Protocol == "" {
		regFrame.Protocol = "http"
	}

	// Encrypt and send registration request
	regData, err := json.Marshal(regFrame)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %w", err)
	}

	encryptedRegData, err := cipher.Encrypt(regData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt registration: %w", err)
	}

	if err := conn.Write(ctx, websocket.MessageBinary, encryptedRegData); err != nil {
		return nil, fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for registration response
	_, responseData, err := conn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read registration response: %w", err)
	}

	// Decrypt response
	decryptedResponse, err := cipher.Decrypt(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt registration response: %w", err)
	}

	var regResp RegisterResponseFrame
	if err := json.Unmarshal(decryptedResponse, &regResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	if regResp.Type != "register_response" {
		return nil, fmt.Errorf("unexpected response type: %s", regResp.Type)
	}

	if !regResp.Success {
		return nil, fmt.Errorf("registration failed: %s", regResp.Error)
	}

	// Convert to RegisterResp format for compatibility
	return &RegisterResp{
		ID:          regResp.ID,
		Secret:      regResp.Secret,
		PublicURL:   regResp.PublicURL,
		CustomURL:   regResp.CustomURL,
		UseRedirect: regResp.UseRedirect,
	}, nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func (a *Agent) isWebSocketUpgrade(req *ReqFrame) bool {
	// Check for WebSocket upgrade headers
	var connection, upgrade string
	if conn, exists := req.Headers["Connection"]; exists && len(conn) > 0 {
		connection = conn[0]
	}
	if up, exists := req.Headers["Upgrade"]; exists && len(up) > 0 {
		upgrade = up[0]
	}

	// WebSocket upgrade requires:
	// 1. Connection: upgrade (case-insensitive)
	// 2. Upgrade: websocket (case-insensitive)
	// 3. Usually GET method
	return strings.ToLower(connection) == "upgrade" &&
		strings.ToLower(upgrade) == "websocket" &&
		req.Method == "GET"
}

// handleWebSocketUpgrade handles WebSocket upgrade and establishes bidirectional forwarding
func (a *Agent) handleWebSocketUpgrade(ctx context.Context, req *ReqFrame, writeEncrypted func(v any) error) {
	// Step 1: Establish WebSocket connection to local service
	localConn, err := a.establishLocalWebSocket(req)
	if err != nil {
		log.Printf("AGENT WEBSOCKET: Failed to establish local WebSocket connection | ReqID: %s | Error: %v",
			req.ReqID, err)
		// Send error response
		resp := RespFrame{
			Type:    "resp",
			ReqID:   req.ReqID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain"}},
			Body:    []byte("WebSocket upgrade failed"),
		}
		writeEncrypted(resp)
		return
	}
	defer localConn.Close(websocket.StatusNormalClosure, "Agent connection closed")

	// Step 2: Send successful upgrade response to server
	resp := RespFrame{
		Type:   "websocket_upgrade_success",
		ReqID:  req.ReqID,
		Status: http.StatusSwitchingProtocols,
		Headers: map[string][]string{
			"Upgrade":    {"websocket"},
			"Connection": {"Upgrade"},
		},
		Body: []byte{},
	}

	if err := writeEncrypted(resp); err != nil {
		log.Printf("AGENT WEBSOCKET: Failed to send upgrade response | ReqID: %s | Error: %v",
			req.ReqID, err)
		return
	}

	log.Printf("AGENT WEBSOCKET: Upgrade successful, starting bidirectional forwarding | ReqID: %s",
		req.ReqID)

	// Step 3: Start bidirectional WebSocket frame forwarding
	a.forwardWebSocketFrames(ctx, req.ReqID, localConn, writeEncrypted)
}

// establishLocalWebSocket establishes WebSocket connection to local service
func (a *Agent) establishLocalWebSocket(req *ReqFrame) (*websocket.Conn, error) {
	// Build WebSocket URL
	target := strings.Replace(a.LocalURL, "http://", "ws://", 1)
	target = strings.Replace(target, "https://", "wss://", 1)
	target += req.Path
	if req.Query != "" {
		target += "?" + req.Query
	}

	// Fix IPv6 localhost issue
	target = strings.Replace(target, "ws://localhost:", "ws://127.0.0.1:", 1)
	target = strings.Replace(target, "wss://localhost:", "wss://127.0.0.1:", 1)

	log.Printf("AGENT WEBSOCKET: Connecting to local service | Target: %s | ReqID: %s",
		target, req.ReqID)

	// Prepare headers for WebSocket connection
	headers := http.Header{}
	for k, vs := range req.Headers {
		// Skip upgrade-related headers - they'll be set by websocket client
		if strings.ToLower(k) == "connection" ||
			strings.ToLower(k) == "upgrade" ||
			strings.ToLower(k) == "sec-websocket-key" ||
			strings.ToLower(k) == "sec-websocket-version" {
			continue
		}
		for _, v := range vs {
			headers.Add(k, v)
		}
	}

	// Establish WebSocket connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, target, &websocket.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial local WebSocket: %w", err)
	}

	// Register connection for bidirectional forwarding
	webSocketMutex.Lock()
	webSocketConnections[req.ReqID] = conn
	webSocketMutex.Unlock()

	return conn, nil
}

// forwardWebSocketFrames handles bidirectional WebSocket frame forwarding
func (a *Agent) forwardWebSocketFrames(ctx context.Context, reqID string, localConn *websocket.Conn, writeEncrypted func(v any) error) {
	// Create context for WebSocket forwarding
	wsCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel to signal completion
	done := make(chan struct{})
	errorChan := make(chan error, 2)

	// Forward frames from local WebSocket to tunnel server
	go func() {
		defer func() {
			select {
			case done <- struct{}{}:
			default:
			}
		}()

		for {
			select {
			case <-wsCtx.Done():
				return
			default:
			}

			// Read frame from local WebSocket
			msgType, data, err := localConn.Read(wsCtx)
			if err != nil {
				closeStatus := websocket.CloseStatus(err)
				if closeStatus != websocket.StatusNormalClosure && closeStatus != websocket.StatusGoingAway {
					log.Printf("AGENT WEBSOCKET: Error reading from local WebSocket | ReqID: %s | Error: %v",
						reqID, err)
					errorChan <- err
				}
				return
			}

			// Forward frame to tunnel server
			frame := WebSocketFrame{
				Type:        "websocket_frame",
				ReqID:       reqID,
				MessageType: int(msgType),
				Data:        data,
				Direction:   "to_server", // local -> server
			}

			if err := writeEncrypted(frame); err != nil {
				log.Printf("AGENT WEBSOCKET: Error forwarding frame to server | ReqID: %s | Error: %v",
					reqID, err)
				errorChan <- err
				return
			}

			log.Printf("AGENT WEBSOCKET: Forwarded frame to server | ReqID: %s | Type: %d | Size: %d bytes",
				reqID, msgType, len(data))
		}
	}()

	// Wait for completion or error
	select {
	case <-done:
		log.Printf("AGENT WEBSOCKET: Frame forwarding completed | ReqID: %s", reqID)
	case err := <-errorChan:
		log.Printf("AGENT WEBSOCKET: Frame forwarding failed | ReqID: %s | Error: %v", reqID, err)
	case <-wsCtx.Done():
		log.Printf("AGENT WEBSOCKET: Frame forwarding cancelled | ReqID: %s", reqID)
	}

	// Send close frame to server
	closeFrame := WebSocketFrame{
		Type:      "websocket_close",
		ReqID:     reqID,
		Direction: "to_server",
	}
	writeEncrypted(closeFrame)
}

// WebSocket connection tracking
var (
	webSocketConnections = make(map[string]*websocket.Conn)
	webSocketMutex       sync.RWMutex
)

// handleWebSocketFrame forwards frames from server to local WebSocket
func (a *Agent) handleWebSocketFrame(frame *WebSocketFrame) {
	webSocketMutex.RLock()
	conn, exists := webSocketConnections[frame.ReqID]
	webSocketMutex.RUnlock()

	if !exists {
		log.Printf("AGENT WEBSOCKET: No local connection found for ReqID: %s", frame.ReqID)
		return
	}

	// Forward frame to local WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := conn.Write(ctx, websocket.MessageType(frame.MessageType), frame.Data)
	if err != nil {
		log.Printf("AGENT WEBSOCKET: Error writing frame to local WebSocket | ReqID: %s | Error: %v",
			frame.ReqID, err)
		// Remove failed connection
		webSocketMutex.Lock()
		delete(webSocketConnections, frame.ReqID)
		webSocketMutex.Unlock()
		conn.Close(websocket.StatusInternalError, "Write failed")
		return
	}

	log.Printf("AGENT WEBSOCKET: Forwarded frame from server to local | ReqID: %s | Type: %d | Size: %d bytes",
		frame.ReqID, frame.MessageType, len(frame.Data))
}

// handleWebSocketClose handles WebSocket close from server
func (a *Agent) handleWebSocketClose(frame *WebSocketFrame) {
	webSocketMutex.Lock()
	conn, exists := webSocketConnections[frame.ReqID]
	if exists {
		delete(webSocketConnections, frame.ReqID)
	}
	webSocketMutex.Unlock()

	if exists {
		log.Printf("AGENT WEBSOCKET: Closing local WebSocket connection | ReqID: %s", frame.ReqID)
		conn.Close(websocket.StatusNormalClosure, "Server closed connection")
	}
}

// handleHttpRequest processes HTTP requests (existing logic)
func (a *Agent) handleHttpRequest(ctx context.Context, req *ReqFrame, writeEncrypted func(v any) error, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Check if connection is still alive before processing
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Check for WebSocket upgrade request
		if a.isWebSocketUpgrade(req) {
			log.Printf("AGENT: WebSocket upgrade detected | ReqID: %s | TunnelID: %s | Path: %s",
				req.ReqID, a.ID, req.Path)
			a.handleWebSocketUpgrade(ctx, req, writeEncrypted)
			return
		}

		status, hdr, body, ferr := a.forward(req)

		// Check if this is a streaming response
		if ferr == nil && string(body) == "STREAMING_RESPONSE" {
			log.Printf("AGENT: Starting streaming response | ReqID: %s | TunnelID: %s | Status: %d",
				req.ReqID, a.ID, status)

			// DIAGNOSTIC: Log the decision to handle streaming
			log.Printf("AGENT: Detected STREAMING_RESPONSE indicator, calling handleStreamingRequest | ReqID: %s | TunnelID: %s | Status: %d | Headers: %+v",
				req.ReqID, a.ID, status, hdr)

			a.handleStreamingRequest(ctx, req, status, hdr, writeEncrypted)
			return
		}

		resp := RespFrame{
			Type:    "resp",
			ReqID:   req.ReqID,
			Status:  status,
			Headers: hdr,
			Body:    body,
		}
		if ferr != nil {
			log.Printf("AGENT: Request forwarding failed, returning 502 Bad Gateway | ReqID: %s | TunnelID: %s | Error: %v",
				req.ReqID, a.ID, ferr)
			resp.Status = http.StatusBadGateway
			resp.Headers = map[string][]string{"Content-Type": {"text/plain"}}
			resp.Body = []byte(ferr.Error())
		} else {
			log.Printf("AGENT: Request completed successfully | ReqID: %s | TunnelID: %s | Status: %d | BodySize: %d",
				req.ReqID, a.ID, status, len(body))
		}

		// Check if connection is still alive before writing
		select {
		case <-ctx.Done():
			return
		default:
			// Check response size before encryption
			respData := mustJSON(resp)
			if len(respData) > crypto.MaxPlaintextSize {
				// Response too large, send error instead
				errResp := RespFrame{
					Type:    "resp",
					ReqID:   req.ReqID,
					Status:  http.StatusInsufficientStorage,
					Headers: map[string][]string{"Content-Type": {"text/plain"}},
					Body:    []byte("Response too large to send through tunnel"),
				}
				if err := writeEncrypted(errResp); err != nil {
					select {
					case <-ctx.Done():
						// Connection was closed, this is expected
					default:
						fmt.Printf("Error writing error response for req_id %s: %v\n", req.ReqID, err)
					}
				}
				return
			}

			if err := writeEncrypted(resp); err != nil {
				// Only log if it's not due to context cancellation
				select {
				case <-ctx.Done():
					// Connection was closed, this is expected
				default:
					fmt.Printf("Error writing response for req_id %s: %v\n", req.ReqID, err)
				}
			}
		}
	}()
}

// handleTcpConnect establishes a new TCP connection to the local service
func (a *Agent) handleTcpConnect(ctx context.Context, frame *TcpConnectFrame, writeEncrypted func(v any) error) {
	// Connect to local TCP service
	target := fmt.Sprintf("%s:%d", strings.Split(a.LocalURL, "://")[1], frame.Port)
	if strings.Contains(a.LocalURL, "://") {
		// Extract host from URL
		u, err := url.Parse(a.LocalURL)
		if err == nil {
			target = fmt.Sprintf("%s:%d", u.Hostname(), frame.Port)
		}
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		// Send disconnect frame on connection failure
		disconnectFrame := TcpDisconnectFrame{
			Type:   "tcp_disconnect",
			ConnID: frame.ConnID,
			Reason: fmt.Sprintf("failed to connect: %v", err),
		}
		writeEncrypted(disconnectFrame)
		return
	}

	// Store the connection
	a.tcpConnsMu.Lock()
	a.tcpConns[frame.ConnID] = conn
	a.tcpConnsMu.Unlock()

	// Start reading from TCP connection and sending to server
	go func() {
		defer func() {
			conn.Close()
			a.tcpConnsMu.Lock()
			delete(a.tcpConns, frame.ConnID)
			a.tcpConnsMu.Unlock()

			disconnectFrame := TcpDisconnectFrame{
				Type:   "tcp_disconnect",
				ConnID: frame.ConnID,
				Reason: "connection closed",
			}
			writeEncrypted(disconnectFrame)
		}()

		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			dataFrame := TcpDataFrame{
				Type:   "tcp_data",
				ConnID: frame.ConnID,
				Data:   buf[:n],
			}

			if err := writeEncrypted(dataFrame); err != nil {
				return
			}
		}
	}()
}

// handleTcpData forwards TCP data to the local connection
func (a *Agent) handleTcpData(frame *TcpDataFrame) {
	a.tcpConnsMu.Lock()
	conn, ok := a.tcpConns[frame.ConnID]
	a.tcpConnsMu.Unlock()

	if ok {
		_, err := conn.Write(frame.Data)
		if err != nil {
			// Connection broken, clean up
			conn.Close()
			a.tcpConnsMu.Lock()
			delete(a.tcpConns, frame.ConnID)
			a.tcpConnsMu.Unlock()
		}
	}
}

// handleTcpDisconnect closes the TCP connection
func (a *Agent) handleTcpDisconnect(frame *TcpDisconnectFrame) {
	a.tcpConnsMu.Lock()
	conn, ok := a.tcpConns[frame.ConnID]
	if ok {
		delete(a.tcpConns, frame.ConnID)
	}
	a.tcpConnsMu.Unlock()

	if ok {
		conn.Close()
	}
}

// Helper function for SHA256 hash
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// maskSecret returns a masked version of the secret for logging
func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "****" + secret[len(secret)-4:]
}

// calculateBackoff returns exponential backoff delay with max cap
func calculateBackoff(failures int, baseDelay time.Duration, maxDelay time.Duration) time.Duration {
	if failures <= 0 {
		return baseDelay
	}

	// Exponential backoff: baseDelay * 2^failures
	delay := baseDelay
	for i := 0; i < failures && delay < maxDelay/2; i++ {
		delay *= 2
	}

	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// handleChunkedResponse processes chunked response frames and assembles them
func (a *Agent) handleChunkedResponse(chunk *ChunkedRespFrame, writeEncrypted func(v any) error) {
	a.chunkedRespMu.Lock()
	defer a.chunkedRespMu.Unlock()

	// Get or create chunked response tracker
	resp, exists := a.chunkedResps[chunk.ReqID]
	if !exists {
		resp = &ChunkedResponse{
			Status:         chunk.Status,
			Headers:        chunk.Headers,
			Chunks:         make(map[int][]byte),
			TotalChunks:    chunk.TotalChunks,
			ReceivedChunks: 0,
		}
		a.chunkedResps[chunk.ReqID] = resp
	}

	// Store the chunk data
	resp.Chunks[chunk.ChunkIndex] = chunk.Data
	resp.ReceivedChunks++

	// Check if we have all chunks
	if resp.ReceivedChunks == resp.TotalChunks {
		// Assemble the complete response
		var body []byte
		for i := 0; i < resp.TotalChunks; i++ {
			chunkData, ok := resp.Chunks[i]
			if !ok {
				fmt.Printf("Missing chunk %d for request %s\n", i, chunk.ReqID)
				delete(a.chunkedResps, chunk.ReqID)
				return
			}
			body = append(body, chunkData...)
		}

		// Log the assembled response
		fmt.Printf("Assembled chunked response for req_id %s: %d bytes, status: %d\n", chunk.ReqID, len(body), resp.Status)

		// Clean up
		delete(a.chunkedResps, chunk.ReqID)
	}
}

// classifyNetworkError determines the type of network error
func classifyNetworkError(err error) error {
	if err == nil {
		return nil
	}

	// Check for DNS resolution errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrDNSFailure
	}

	// Check for connection refused or network unreachable
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return ErrNetworkFailure
		}
	}

	// Check for context timeout (includes DNS timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		if strings.Contains(err.Error(), "dns") || strings.Contains(err.Error(), "lookup") {
			return ErrDNSFailure
		}
		return ErrNetworkFailure
	}

	// Check for common network errors by string matching
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "dns") {
		return ErrDNSFailure
	}
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "network unreachable") {
		return ErrNetworkFailure
	}

	// Default to network failure for unknown connection errors
	return ErrNetworkFailure
}

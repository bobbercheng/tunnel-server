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
)

type RegisterReq struct {
	Protocol  string `json:"protocol"`           // "http" or "tcp"
	Port      int    `json:"port"`               // for TCP tunnels, the local port being tunneled
	CustomURL string `json:"custom_url,omitempty"` // custom URL like "bob/chatbot"
}

type RegisterResp struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`
	CustomURL string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol  string `json:"protocol"`
	TcpPort   int    `json:"tcp_port,omitempty"` // for TCP tunnels
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
	Type      string `json:"type"`               // "register"
	Protocol  string `json:"protocol"`           // "http" or "tcp"
	Port      int    `json:"port"`               // for TCP tunnels, the local port being tunneled
	CustomURL string `json:"custom_url,omitempty"` // custom URL like "bob/chatbot"
}

// RegisterResponseFrame is the server's response to registration (encrypted)
type RegisterResponseFrame struct {
	Type      string `json:"type"`               // "register_response"
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`        // Default /__pub__/{id} or /__tcp__/{id}
	CustomURL string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol  string `json:"protocol"`
	TcpPort   int    `json:"tcp_port,omitempty"` // for TCP tunnels
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`    // error message if Success is false
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
}

type PongFrame struct {
	Type      string    `json:"type"`      // "pong"
	Timestamp time.Time `json:"timestamp"` // original ping timestamp
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
)

type Agent struct {
	ServerURL string
	LocalURL  string
	ID        string
	Secret    string
	Protocol  string // "http" or "tcp"
	Port      int    // for TCP tunnels
	CustomURL string // custom URL for this tunnel

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

		if errors.Is(err, ErrUnauthorized) {
			fmt.Println("Credentials rejected, re-registering for a new tunnel...")
			reg, regErr := a.register()
			if regErr != nil {
				fmt.Println("Failed to re-register:", regErr)
				fmt.Println("Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			}
			a.ID, a.Secret = reg.ID, reg.Secret
			// Reset failure counters after successful re-registration
			a.consecutiveDNSFailures = 0
			a.consecutiveNetworkFailures = 0
			fmt.Println("Re-registered successfully!")
			fmt.Println("  ID:", a.ID)
			fmt.Println("  Secret:", a.Secret)
			fmt.Println("  New Public URL:", reg.PublicURL)
			if reg.CustomURL != "" {
				fmt.Println("  Custom URL:", reg.CustomURL)
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

	fmt.Println("Connection established successfully with encryption.")

	// If this is a new connection (no ID/Secret), perform registration over encrypted WebSocket
	if a.ID == "" || a.Secret == "" {
		fmt.Println("No tunnel id/secret provided, registering new tunnel...")
		err := a.registerOverWebSocket(ctx, ws, cipher)
		if err != nil {
			return fmt.Errorf("WebSocket registration failed: %w", err)
		}
		fmt.Println("Registered successfully!")
		fmt.Println("  ID:", a.ID)
		fmt.Println("  Secret:", a.Secret)
		// Note: Public URL and Custom URL will be logged by registerOverWebSocket
	}

	// Create a context that will be cancelled when the connection closes
	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// Track active request handlers
	var wg sync.WaitGroup

	// Mutex to protect websocket writes
	var writeMu sync.Mutex

	// Channel to signal connection closure
	done := make(chan struct{})

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

	// Start ping monitoring goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Ping every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Send ping
				pingFrame := PingFrame{
					Type:      "ping",
					Timestamp: time.Now(),
				}

				if err := writeEncrypted(pingFrame); err != nil {
					log.Printf("Failed to send ping: %v", err)
					cancelCtx()
					return
				}

				// Check if last pong is too old
				a.pingMu.RLock()
				lastPong := a.lastPong
				a.pingMu.RUnlock()

				if time.Since(lastPong) > 90*time.Second { // 3 missed pings
					log.Println("Connection appears to be dead (no pong received), closing...")
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
					continue
				}
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
			case "ping":
				// Respond to server ping with pong
				var pingFrame PingFrame
				if err := json.Unmarshal(plaintext, &pingFrame); err != nil {
					continue
				}
				pongFrame := PongFrame{
					Type:      "pong",
					Timestamp: pingFrame.Timestamp,
				}
				if err := writeEncrypted(pongFrame); err != nil {
					log.Printf("Failed to send pong: %v", err)
				}
			case "pong":
				// Update last pong time for connection health monitoring
				a.pingMu.Lock()
				a.lastPong = time.Now()
				a.pingMu.Unlock()
			default:
				continue
			}
		}
	}()

	// Wait for connection to close
	<-done

	// Cancel context to stop all handlers
	cancelCtx()

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

	return nil
}

func (a *Agent) forward(rd *ReqFrame) (int, map[string][]string, []byte, error) {
	target := a.LocalURL + rd.Path
	if rd.Query != "" {
		target += "?" + rd.Query
	}
	req, err := http.NewRequest(rd.Method, target, bytes.NewReader(rd.Body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range rd.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "text/stream") ||
		strings.Contains(contentType, "application/stream") {
		return handleStreamingResponse(resp)
	}

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, 8*1024*1024) // 8MB limit
	b, err := io.ReadAll(limitedReader)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}

	// Check if we hit the limit
	if len(b) == 8*1024*1024 {
		// Try to read one more byte to see if there's more data
		extra := make([]byte, 1)
		if n, _ := resp.Body.Read(extra); n > 0 {
			return resp.StatusCode, resp.Header, nil, fmt.Errorf("response body too large (>8MB)")
		}
	}

	return resp.StatusCode, resp.Header, b, nil
}

func handleStreamingResponse(resp *http.Response) (int, map[string][]string, []byte, error) {
	var buffer bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		totalRead := 0
		maxSize := 8 * 1024 * 1024 // 8MB limit

		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			default:
				n, err := resp.Body.Read(buf)
				if n > 0 {
					if totalRead+n > maxSize {
						done <- fmt.Errorf("streaming response too large (>8MB)")
						return
					}
					buffer.Write(buf[:n])
					totalRead += n
				}
				if err != nil {
					if err == io.EOF {
						done <- nil
						return
					}
					done <- err
					return
				}
			}
		}
	}()

	err := <-done
	if err != nil && err != context.DeadlineExceeded {
		return resp.StatusCode, resp.Header, buffer.Bytes(), nil
	}
	return resp.StatusCode, resp.Header, buffer.Bytes(), nil
}

// registerOverWebSocket performs registration over encrypted WebSocket connection
func (a *Agent) registerOverWebSocket(ctx context.Context, ws *websocket.Conn, cipher *crypto.StreamCipher) error {
	// Create registration frame
	regFrame := &RegisterFrame{
		Type:      "register",
		Protocol:  a.Protocol,
		Port:      a.Port,
		CustomURL: a.CustomURL,
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

	// Store the registration details
	a.ID = regResp.ID
	a.Secret = regResp.Secret
	
	// Log the URLs
	fmt.Println("  Public URL:", regResp.PublicURL)
	if regResp.CustomURL != "" {
		fmt.Println("  Custom URL:", regResp.CustomURL)
	}

	return nil
}

func (a *Agent) register() (*RegisterResp, error) {
	req := RegisterReq{
		Protocol:  a.Protocol,
		Port:      a.Port,
		CustomURL: a.CustomURL,
	}

	// Default to HTTP if not specified
	if req.Protocol == "" {
		req.Protocol = "http"
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(a.ServerURL+"/__register__", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r RegisterResp
	return &r, json.NewDecoder(resp.Body).Decode(&r)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
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

		status, hdr, body, ferr := a.forward(req)

		resp := RespFrame{
			Type:    "resp",
			ReqID:   req.ReqID,
			Status:  status,
			Headers: hdr,
			Body:    body,
		}
		if ferr != nil {
			resp.Status = http.StatusBadGateway
			resp.Headers = map[string][]string{"Content-Type": {"text/plain"}}
			resp.Body = []byte(ferr.Error())
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

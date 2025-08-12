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
	Protocol string `json:"protocol"` // "http" or "tcp"
	Port     int    `json:"port"`     // for TCP tunnels, the local port being tunneled
}

type RegisterResp struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`
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

// HandshakeFrame is used for initial key exchange
type HandshakeFrame struct {
	Type string `json:"type"` // "handshake"
	Salt string `json:"salt"` // base64 encoded salt
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

var (
	ErrUnauthorized = errors.New("unauthorized: credentials rejected by server")
	ErrNetworkFailure = errors.New("network failure: unable to reach server")
	ErrDNSFailure = errors.New("dns failure: unable to resolve server hostname")
)

type Agent struct {
	ServerURL string
	LocalURL  string
	ID        string
	Secret    string
	Protocol  string // "http" or "tcp"
	Port      int    // for TCP tunnels
	
	// Retry state
	consecutiveDNSFailures     int
	consecutiveNetworkFailures int
	
	// TCP connection management
	tcpConnsMu sync.Mutex
	tcpConns   map[string]net.Conn // connID -> TCP connection
}

func (a *Agent) Run() {
	if a.ID == "" || a.Secret == "" {
		fmt.Println("No tunnel id/secret provided, registering new tunnel...")
		reg, err := a.register()
		if err != nil {
			fmt.Println("FATAL: initial registration failed:", err)
			return
		}
		a.ID, a.Secret = reg.ID, reg.Secret
		fmt.Println("Registered successfully!")
		fmt.Println("  ID:", a.ID)
		fmt.Println("  Secret:", a.Secret)
		fmt.Println("  Public URL:", reg.PublicURL)
	}

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
	
	dialCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wsURL := fmt.Sprintf("%s/ws?id=%s&secret=%s", a.ServerURL, url.QueryEscape(a.ID), url.QueryEscape(a.Secret))

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

	// Set larger message size limit (10MB instead of default 32KB)
	ws.SetReadLimit(10 * 1024 * 1024)

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

	// Create cipher with the same master secret but isServer=false
	masterSecret := sha256Sum([]byte(a.Secret))
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

func (a *Agent) register() (*RegisterResp, error) {
	req := RegisterReq{
		Protocol: a.Protocol,
		Port:     a.Port,
	}
	
	// Default to HTTP if not specified
	if req.Protocol == "" {
		req.Protocol = "http"
	}
	
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	
	resp, err := http.Post(a.ServerURL+"/register", "application/json", bytes.NewReader(reqBody))
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

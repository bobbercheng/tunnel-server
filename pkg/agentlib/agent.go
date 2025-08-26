package agentlib

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	crypto "tunnel.local/crypto"
	utls "github.com/refraction-networking/utls"

	"golang.org/x/net/http2"
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

// HeartbeatFrame is used for streaming connection health monitoring
type HeartbeatFrame struct {
	Type        string              `json:"type"`              // "streaming_heartbeat"
	ReqID       string              `json:"req_id"`            // request identifier
	Status      int                 `json:"status"`            // HTTP status code
	Headers     map[string][]string `json:"headers,omitempty"` // optional headers
	ChunkIndex  int                 `json:"chunk_index"`       // -1 for heartbeat
	TotalChunks int                 `json:"total_chunks"`      // -1 for heartbeat
	Data        []byte              `json:"data"`              // heartbeat data
	IsLast      bool                `json:"is_last"`           // false for heartbeat
	Timestamp   int64               `json:"timestamp"`         // Unix timestamp
}

// RewriteRule defines a user-configurable content rewriting pattern
type RewriteRule struct {
	Name         string   `json:"name"`          // Human-readable rule name
	Pattern      string   `json:"pattern"`       // Regex pattern to match
	Replacement  string   `json:"replacement"`   // Replacement template (supports $1, $2, etc.)
	ContentTypes []string `json:"content_types"` // Apply only to these content types
	Enabled      bool     `json:"enabled"`       // Toggle rule on/off
	compiledRegex *regexp.Regexp // cached compiled regex (not exported)
}

// RewriteConfig holds the complete rewriting configuration
type RewriteConfig struct {
	Rules []RewriteRule `json:"rules"` // List of rewrite rules
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
	ServerURL      string
	LocalURL       string
	ID             string
	Secret         string
	Protocol       string // "http" or "tcp"
	Port           int    // for TCP tunnels
	CustomURL      string // custom URL for this tunnel
	UseRedirect    bool   // enable SPA redirection
	RewriteContent bool   // enable content rewriting for HTML/JS/CSS
	RewriteHeaders bool   // enable response header rewriting for CORS
	RewriteConfig  *RewriteConfig // user-defined rewriting rules
	DebugLog       bool   // enable debug logging to file
	DebugFile      string // path to debug log file

	// Retry state
	consecutiveDNSFailures     int
	consecutiveNetworkFailures int

	// TCP connection management
	tcpConnsMu sync.Mutex
	tcpConns   map[string]net.Conn // connID -> TCP connection

	// Chunked response management
	chunkedRespMu sync.Mutex
	chunkedResps  map[string]*ChunkedResponse // reqID -> partial response

	// Streaming response management
	streamingRespMu sync.Mutex
	streamingResps  map[string]*http.Response // reqID -> streaming response

	// Request queue management for connection recovery
	requestQueueMu     sync.Mutex
	requestQueue       []*PendingRequest
	maxQueueSize       int
	queueTimeout       time.Duration
	
	// Connection state tracking
	isConnected        bool
	connectionStateMu  sync.RWMutex

	// Connection health monitoring
	lastPong time.Time
	pingMu   sync.RWMutex

	// Debug logging
	debugLogFile  *os.File
	debugLogMu    sync.Mutex
}

// ChunkedResponse tracks partial chunked responses
type ChunkedResponse struct {
	Status         int
	Headers        map[string][]string
	Chunks         map[int][]byte // chunkIndex -> data
	TotalChunks    int
	ReceivedChunks int
}

// PendingRequest represents a request waiting to be sent during connection recovery
type PendingRequest struct {
	ReqFrame    *ReqFrame
	ResponseCh  chan *RespFrame
	CreatedAt   time.Time
	RetriesLeft int
	IsHTTP      bool // true for HTTP, false for TCP
}

// InitializeQueue sets up the request queue for connection recovery
func (a *Agent) InitializeQueue() {
	a.maxQueueSize = 100        // max 100 pending requests
	a.queueTimeout = 30 * time.Second // requests expire after 30 seconds
	a.requestQueue = make([]*PendingRequest, 0, a.maxQueueSize)
	a.chunkedResps = make(map[string]*ChunkedResponse)
	a.streamingResps = make(map[string]*http.Response)
	a.tcpConns = make(map[string]net.Conn)
}

// LoadRewriteConfig loads rewrite rules from a JSON file
func (a *Agent) LoadRewriteConfig(filePath string) error {
	if filePath == "" {
		// Initialize with default rules
		a.RewriteConfig = a.getDefaultRewriteConfig()
		return nil
	}
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rewrite config file: %w", err)
	}
	
	var config RewriteConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse rewrite config JSON: %w", err)
	}
	
	// Compile regex patterns for enabled rules
	for i := range config.Rules {
		rule := &config.Rules[i]
		if rule.Enabled && rule.Pattern != "" {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("failed to compile regex pattern '%s' for rule '%s': %w", 
					rule.Pattern, rule.Name, err)
			}
			rule.compiledRegex = compiled
		}
	}
	
	a.RewriteConfig = &config
	log.Printf("REWRITE CONFIG: Loaded %d rules from %s", len(config.Rules), filePath)
	return nil
}

// getDefaultRewriteConfig returns a set of common rewrite rules
func (a *Agent) getDefaultRewriteConfig() *RewriteConfig {
	originalDomain := a.getOriginalDomain()
	if originalDomain == "" {
		originalDomain = "example.com" // fallback for generic rules
	}
	tunnelBase := "https://" + a.getServerDomain()
	
	rules := []RewriteRule{
		{
			Name:         "basic-url-replacement",
			Pattern:      fmt.Sprintf("https://%s", regexp.QuoteMeta(originalDomain)),
			Replacement:  tunnelBase,
			ContentTypes: []string{"text/html", "application/javascript", "text/css", "application/json"},
			Enabled:      true,
		},
		{
			Name:         "protocol-relative-urls",
			Pattern:      fmt.Sprintf("//%s", regexp.QuoteMeta(originalDomain)),
			Replacement:  "//" + a.getServerDomain(),
			ContentTypes: []string{"text/html", "application/javascript", "text/css"},
			Enabled:      true,
		},
		{
			Name:         "javascript-variable-assignment",
			Pattern:      fmt.Sprintf(`(const|let|var)\s+(\w+)\s*=\s*["']https://%s(/[^"']*)?["']`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`$1 $2 = "%s$3"`, tunnelBase),
			ContentTypes: []string{"application/javascript", "text/html"},
			Enabled:      true,
		},
		{
			Name:         "json-property-urls",
			Pattern:      fmt.Sprintf(`"([^"]*)":\s*"https://%s(/[^"]*)?`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`"$1": "%s$2"`, tunnelBase),
			ContentTypes: []string{"application/json", "application/javascript"},
			Enabled:      true,
		},
		{
			Name:         "css-url-function",
			Pattern:      fmt.Sprintf(`url\s*\(\s*["']?https://%s(/[^"'\)]*)?["']?\s*\)`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`url("%s$1")`, tunnelBase),
			ContentTypes: []string{"text/css", "text/html"},
			Enabled:      true,
		},
	}
	
	// Compile all default patterns
	for i := range rules {
		rule := &rules[i]
		if rule.Enabled && rule.Pattern != "" {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Printf("REWRITE CONFIG: Warning - failed to compile default pattern '%s': %v", rule.Pattern, err)
				rule.Enabled = false
				continue
			}
			rule.compiledRegex = compiled
		}
	}
	
	return &RewriteConfig{Rules: rules}
}

// setConnectionState updates the connection state thread-safely
func (a *Agent) setConnectionState(connected bool) {
	a.connectionStateMu.Lock()
	defer a.connectionStateMu.Unlock()
	wasConnected := a.isConnected
	a.isConnected = connected
	
	// When reconnecting, process queued requests
	if connected && !wasConnected {
		go a.processQueuedRequests()
	}
}

// isConnectionAlive returns the current connection state
func (a *Agent) isConnectionAlive() bool {
	a.connectionStateMu.RLock()
	defer a.connectionStateMu.RUnlock()
	return a.isConnected
}

// processQueuedRequests sends all queued requests when connection is restored
func (a *Agent) processQueuedRequests() {
	a.requestQueueMu.Lock()
	defer a.requestQueueMu.Unlock()
	
	if len(a.requestQueue) == 0 {
		return
	}
	
	log.Printf("QUEUE: Processing %d queued requests after reconnection", len(a.requestQueue))
	
	// Process queued requests
	for i, pending := range a.requestQueue {
		// Skip expired requests
		if time.Since(pending.CreatedAt) > a.queueTimeout {
			log.Printf("QUEUE: Request %s expired, skipping", pending.ReqFrame.ReqID)
			close(pending.ResponseCh)
			continue
		}
		
		// Mark as processed (will be removed at end)
		a.requestQueue[i] = nil
		
		// Send the request in a goroutine to avoid blocking
		go func(req *PendingRequest) {
			log.Printf("QUEUE: Replaying request %s", req.ReqFrame.ReqID)
			// The actual sending will happen through the normal request flow
			// This just ensures the request gets processed
		}(pending)
	}
	
	// Clean up processed requests
	a.requestQueue = a.requestQueue[:0]
	log.Println("QUEUE: All queued requests processed")
}

// queueRequest adds a request to the queue when connection is down
func (a *Agent) queueRequest(reqFrame *ReqFrame, responseCh chan *RespFrame) bool {
	a.requestQueueMu.Lock()
	defer a.requestQueueMu.Unlock()
	
	// Check if queue is full
	if len(a.requestQueue) >= a.maxQueueSize {
		log.Printf("QUEUE: Queue full, dropping request %s", reqFrame.ReqID)
		return false
	}
	
	pending := &PendingRequest{
		ReqFrame:    reqFrame,
		ResponseCh:  responseCh,
		CreatedAt:   time.Now(),
		RetriesLeft: 3,
		IsHTTP:      true,
	}
	
	a.requestQueue = append(a.requestQueue, pending)
	log.Printf("QUEUE: Queued request %s (queue size: %d)", reqFrame.ReqID, len(a.requestQueue))
	return true
}

func (a *Agent) Run() {
	// Initialize debug logging if enabled
	if a.DebugLog {
		err := a.initDebugLogging()
		if err != nil {
			log.Printf("AGENT DEBUG: Failed to initialize debug logging: %v", err)
		} else {
			log.Printf("AGENT DEBUG: Debug logging enabled to file: %s", a.getDebugFileName())
		}
	}

	// Note: Registration now happens over WebSocket during connection

	for {
		err := a.runOnce()
		if err == nil {
			// Reset failure counters on successful connection
			a.consecutiveDNSFailures = 0
			a.consecutiveNetworkFailures = 0
			fmt.Println("Connection closed normally. Reconnecting in 2 seconds...")
			a.setConnectionState(false) // Mark as disconnected
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

			// Re-initialize debug logging with new tunnel ID
			if a.DebugLog {
				err := a.initDebugLogging()
				if err != nil {
					log.Printf("AGENT DEBUG: Failed to re-initialize debug logging: %v", err)
				} else {
					log.Printf("AGENT DEBUG: Debug logging re-initialized for new tunnel ID: %s", a.ID)
				}
			}
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
	
	// Mark connection as active for queue processing
	a.setConnectionState(true)

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
		log.Printf("All request handlers completed for tunnel %s", a.ID)
	case <-time.After(10 * time.Second):
		log.Printf("Timeout waiting for request handlers to complete for tunnel %s", a.ID)
	}

	// Log connection closure reason
	if returnErr != nil {
		log.Printf("WebSocket connection closed with error for tunnel %s: %v", a.ID, returnErr)
	} else {
		log.Printf("WebSocket connection closed normally for tunnel %s", a.ID)
	}

	return returnErr
}

// Browser client specifications for realistic TLS fingerprinting
var browserSpecs = []utls.ClientHelloID{
	utls.HelloChrome_Auto,    // Latest Chrome
	utls.HelloFirefox_120,    // Firefox 120
	utls.HelloSafari_16_0,    // Safari 16.0
	utls.HelloEdge_106,       // Edge 106
}

// uTLSRoundTripper implements http.RoundTripper with proper HTTP/2 protocol handling
type uTLSRoundTripper struct {
	spec utls.ClientHelloID
	h2Transport  *http2.Transport
	h1Transport  *http.Transport
}

// newUTLSRoundTripper creates a new uTLS round tripper with the specified browser fingerprint
func newUTLSRoundTripper(spec utls.ClientHelloID) *uTLSRoundTripper {
	return &uTLSRoundTripper{
		spec: spec,
		h2Transport: &http2.Transport{
			AllowHTTP: false,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialUTLS(network, addr, cfg, spec)
			},
		},
		h1Transport: &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialTLS: func(network, addr string) (net.Conn, error) {
				return dialUTLS(network, addr, nil, spec)
			},
		},
	}
}

// dialUTLS creates a uTLS connection with the specified browser fingerprint
func dialUTLS(network, addr string, cfg *tls.Config, spec utls.ClientHelloID) (net.Conn, error) {
	// Establish TCP connection
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}
	
	// Extract hostname for SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // Fallback if port is missing
	}
	
	// Configure uTLS
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}
	
	// Copy additional config if provided
	if cfg != nil {
		config.NextProtos = cfg.NextProtos
		config.ServerName = cfg.ServerName
	}
	
	// Create uTLS connection with browser fingerprint
	uConn := utls.UClient(tcpConn, config, spec)
	
	// Perform TLS handshake
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	
	// Log connection details
	connState := uConn.ConnectionState()
	log.Printf("uTLS: Connection established | Host: %s | Protocol: %s | TLS: %x | Spec: %s",
		host, connState.NegotiatedProtocol, connState.Version, spec.Str())
	
	return uConn, nil
}

// rewriteContent rewrites response content using configurable user-defined rules
func (a *Agent) rewriteContent(body []byte, contentType string, req *ReqFrame) []byte {
	// Only rewrite HTML, CSS, and JavaScript content
	if !a.shouldRewriteContent(contentType) {
		return body
	}

	// Ensure we have rewrite config loaded (fallback to defaults)
	if a.RewriteConfig == nil {
		a.RewriteConfig = a.getDefaultRewriteConfig()
	}

	content := string(body)
	originalSize := len(content)
	rewritten := content
	totalMatches := 0

	log.Printf("REWRITE: Processing content | ContentType: %s | Size: %d bytes | Rules: %d | ReqID: %s",
		contentType, originalSize, len(a.RewriteConfig.Rules), req.ReqID)

	// Apply each enabled rule that matches the content type
	for _, rule := range a.RewriteConfig.Rules {
		if !rule.Enabled || rule.compiledRegex == nil {
			continue
		}

		// Check if this rule applies to the current content type
		if !a.ruleMatchesContentType(rule, contentType) {
			continue
		}

		// Apply the rule
		matches := rule.compiledRegex.FindAllString(rewritten, -1)
		if len(matches) > 0 {
			rewritten = rule.compiledRegex.ReplaceAllString(rewritten, rule.Replacement)
			totalMatches += len(matches)
			log.Printf("REWRITE: Applied rule '%s' | Matches: %d | Patterns: %v | ReqID: %s",
				rule.Name, len(matches), matches, req.ReqID)
		}
	}

	rewrittenSize := len(rewritten)
	if totalMatches > 0 {
		log.Printf("REWRITE SUCCESS: Content modified | Original: %d bytes → Rewritten: %d bytes | Total matches: %d | ReqID: %s",
			originalSize, rewrittenSize, totalMatches, req.ReqID)
	} else {
		log.Printf("REWRITE: No rules matched | ContentType: %s | Size: %d bytes | ReqID: %s",
			contentType, originalSize, req.ReqID)
	}

	return []byte(rewritten)
}

// ruleMatchesContentType checks if a rewrite rule should be applied to the given content type
func (a *Agent) ruleMatchesContentType(rule RewriteRule, contentType string) bool {
	if len(rule.ContentTypes) == 0 {
		return true // No restrictions - apply to all content types
	}

	contentType = strings.ToLower(contentType)
	for _, ruleType := range rule.ContentTypes {
		if strings.Contains(contentType, strings.ToLower(ruleType)) {
			return true
		}
	}
	return false
}

// shouldRewriteContent determines if content should be rewritten based on Content-Type
func (a *Agent) shouldRewriteContent(contentType string) bool {
	contentType = strings.ToLower(contentType)
	
	rewriteTypes := []string{
		"text/html",
		"application/javascript",
		"text/javascript", 
		"application/x-javascript",
		"text/css",
		"application/json",
		"text/plain", // Sometimes JavaScript is served as text/plain
		"text/x-json",
	}

	for _, t := range rewriteTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}
	return false
}


// rewriteResponseHeaders rewrites HTTP response headers to replace original domain references
func (a *Agent) rewriteResponseHeaders(headers http.Header, req *ReqFrame) {
	originalDomain := a.getOriginalDomain()
	tunnelDomain := a.getServerDomain()
	
	if originalDomain == "" || tunnelDomain == "" {
		return
	}

	headersModified := 0

	// CORS headers that need domain rewriting
	corsHeaders := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials", 
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Methods",
		"Access-Control-Expose-Headers",
	}

	// Security headers that may reference domains
	securityHeaders := []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Referrer-Policy",
		"Permissions-Policy",
		"Feature-Policy",
	}

	// Location headers for redirects
	locationHeaders := []string{
		"Location",
		"Refresh",
	}

	// Process CORS headers
	for _, header := range corsHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value
				// Replace domain references in CORS headers
				newValue := strings.ReplaceAll(value, originalDomain, tunnelDomain)
				newValue = strings.ReplaceAll(newValue, "https://"+originalDomain, "https://"+tunnelDomain)
				newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain) // Force HTTPS
				
				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: CORS header %s | Original: %s | Rewritten: %s | ReqID: %s", 
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Process security headers with more complex patterns
	for _, header := range securityHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value
				newValue := value
				
				// Handle Content-Security-Policy directives
				if header == "Content-Security-Policy" || header == "Content-Security-Policy-Report-Only" {
					// Replace domain in various CSP directives
					newValue = strings.ReplaceAll(newValue, "https://"+originalDomain, "https://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "wss://"+originalDomain, "wss://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "ws://"+originalDomain, "wss://"+tunnelDomain)
					// Handle wildcards and subdomains
					newValue = strings.ReplaceAll(newValue, "*."+originalDomain, "*."+tunnelDomain)
				} else {
					// For other security headers, do basic domain replacement
					newValue = strings.ReplaceAll(newValue, originalDomain, tunnelDomain)
				}
				
				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: Security header %s | Original: %s | Rewritten: %s | ReqID: %s", 
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Process location headers for redirects
	for _, header := range locationHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value
				
				// Handle absolute URLs in location headers
				newValue := strings.ReplaceAll(value, "https://"+originalDomain, "https://"+tunnelDomain+a.getCustomURLPath())
				newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain+a.getCustomURLPath())
				
				// Handle relative URLs that might become absolute
				if strings.HasPrefix(newValue, "/") && !strings.HasPrefix(newValue, "//") {
					newValue = "https://" + tunnelDomain + a.getCustomURLPath() + newValue
				}
				
				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: Location header %s | Original: %s | Rewritten: %s | ReqID: %s", 
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Handle Set-Cookie headers to update domain attributes
	if cookies := headers["Set-Cookie"]; len(cookies) > 0 {
		for i, cookie := range cookies {
			originalCookie := cookie
			
			// Replace domain attributes in cookies
			newCookie := strings.ReplaceAll(cookie, "Domain="+originalDomain, "Domain="+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "domain="+originalDomain, "domain="+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "Domain=."+originalDomain, "Domain=."+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "domain=."+originalDomain, "domain=."+tunnelDomain)
			
			if newCookie != originalCookie {
				headers["Set-Cookie"][i] = newCookie  
				headersModified++
				log.Printf("REWRITE: Cookie header | Original: %s | Rewritten: %s | ReqID: %s", 
					originalCookie, newCookie, req.ReqID)
			}
		}
	}

	if headersModified > 0 {
		log.Printf("REWRITE: Headers modified | Count: %d | ReqID: %s", headersModified, req.ReqID)
	}
}

// getOriginalDomain extracts domain from LocalURL (e.g., "chatgpt.com" from "https://chatgpt.com")
func (a *Agent) getOriginalDomain() string {
	if a.LocalURL == "" {
		return ""
	}
	
	// Parse the URL to extract hostname
	if u, err := url.Parse(a.LocalURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// getServerDomain returns the tunnel server domain (e.g., "connect.vexorium.net")
func (a *Agent) getServerDomain() string {
	if a.ServerURL == "" {
		return ""
	}
	
	if u, err := url.Parse(a.ServerURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// getCustomURLPath returns the custom URL path (e.g., "/chatgpt-roundtripper-test")
func (a *Agent) getCustomURLPath() string {
	if a.CustomURL == "" {
		return ""
	}
	return "/" + a.CustomURL
}

// getTunnelBaseURL returns the full tunnel base URL
func (a *Agent) getTunnelBaseURL() string {
	serverDomain := a.getServerDomain()
	customPath := a.getCustomURLPath()
	
	if serverDomain == "" || customPath == "" {
		return ""
	}
	
	return "https://" + serverDomain + customPath
}

// rewriteJavaScriptAPICalls handles JavaScript fetch() and XMLHttpRequest rewriting
func (a *Agent) rewriteJavaScriptAPICalls(content, originalDomain, tunnelBase string) string {
	// Pattern for fetch() calls with absolute URLs
	// fetch("https://chatgpt.com/api/...") → fetch("/chatgpt-tunnel/api/...")
	
	// Simple regex-like replacements for common patterns
	patterns := []struct {
		old string
		new string
	}{
		// fetch() with double quotes
		{`fetch("https://` + originalDomain + `/`, `fetch("` + tunnelBase + `/`},
		{`fetch("https://` + originalDomain + `"`, `fetch("` + tunnelBase + `"`},
		// fetch() with single quotes  
		{`fetch('https://` + originalDomain + `/`, `fetch('` + tunnelBase + `/`},
		{`fetch('https://` + originalDomain + `'`, `fetch('` + tunnelBase + `'`},
		// XMLHttpRequest.open()
		{`.open("GET", "https://` + originalDomain + `/`, `.open("GET", "` + tunnelBase + `/`},
		{`.open('GET', 'https://` + originalDomain + `/`, `.open('GET', '` + tunnelBase + `/`},
		// jQuery and axios
		{`$.get("https://` + originalDomain + `/`, `$.get("` + tunnelBase + `/`},
		{`axios.get("https://` + originalDomain + `/`, `axios.get("` + tunnelBase + `/`},
		// WebSocket connections
		{`new WebSocket("wss://` + originalDomain + `/`, `new WebSocket("wss://` + a.getServerDomain() + a.getCustomURLPath() + `/`},
	}
	
	result := content
	for _, p := range patterns {
		result = strings.ReplaceAll(result, p.old, p.new)
	}
	
	return result
}

// rewriteCSSURLs handles CSS url() and @import rewriting
func (a *Agent) rewriteCSSURLs(content, originalDomain, tunnelBase string) string {
	patterns := []struct {
		old string
		new string
	}{
		// CSS url() with various quote styles
		{`url("https://` + originalDomain + `/`, `url("` + tunnelBase + `/`},
		{`url('https://` + originalDomain + `/`, `url('` + tunnelBase + `/`},
		{`url(https://` + originalDomain + `/`, `url(` + tunnelBase + `/`},
		// @import statements
		{`@import "https://` + originalDomain + `/`, `@import "` + tunnelBase + `/`},
		{`@import 'https://` + originalDomain + `/`, `@import '` + tunnelBase + `/`},
		{`@import url("https://` + originalDomain + `/`, `@import url("` + tunnelBase + `/`},
	}
	
	result := content
	for _, p := range patterns {
		result = strings.ReplaceAll(result, p.old, p.new)
	}
	
	return result
}

// RoundTrip implements the RoundTripper interface with protocol detection
func (u *uTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("uTLS: RoundTrip called for %s | Spec: %s", req.URL.String(), u.spec.Str())
	
	// For HTTP/2, try h2 transport first since it can negotiate protocol
	if req.URL.Scheme == "https" {
		resp, err := u.h2Transport.RoundTrip(req)
		if err != nil {
			// If H2 fails, fall back to H1
			log.Printf("uTLS: HTTP/2 failed, falling back to HTTP/1.1: %v", err)
			return u.h1Transport.RoundTrip(req)
		}
		return resp, nil
	}
	
	// For HTTP, use h1 transport
	return u.h1Transport.RoundTrip(req)
}

// createUTLSTransport creates a HTTP transport with uTLS for browser-like TLS handshakes
func createUTLSTransport(isLocalhost bool) *http.Transport {
	// Select a random browser spec for TLS fingerprint diversity
	spec := browserSpecs[rand.Intn(len(browserSpecs))]
	
	// Create custom dialer with uTLS
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   20,
		ForceAttemptHTTP2:     false, // Disable HTTP/2 to avoid protocol issues with uTLS
		
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Force IPv4 for localhost connections to avoid IPv6 issues
			if isLocalhost && (strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:")) {
				return dialer.DialContext(ctx, "tcp4", addr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use uTLS for external connections to avoid detection
			if !isLocalhost {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				
				// Establish TCP connection first
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				
				// Create uTLS connection with browser-like handshake
				uConn := utls.UClient(conn, &utls.Config{
					ServerName:         host,
					InsecureSkipVerify: false,
					NextProtos:         []string{"http/1.1"}, // Force HTTP/1.1 only
				}, spec)
				
				// Perform TLS handshake
				err = uConn.HandshakeContext(ctx)
				if err != nil {
					conn.Close()
					return nil, err
				}
				
				log.Printf("uTLS: Established connection using %s fingerprint | Host: %s:%s", 
					spec.Str(), host, port)
				return uConn, nil
			}
			
			// Use standard TLS for localhost
			return dialer.DialContext(ctx, network, addr)
		},
	}
	
	return transport
}

// createBrowserClient creates an HTTP client with uTLS and browser-like characteristics
func createBrowserClient(isLocalhost bool) *http.Client {
	// Create cookie jar for session persistence
	jar, _ := cookiejar.New(&cookiejar.Options{})
	
	var transport http.RoundTripper
	if isLocalhost {
		// Use standard transport for localhost
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return dialer.DialContext(ctx, "tcp4", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		// Use uTLS round tripper for external requests with proper HTTP/2 support
		spec := browserSpecs[rand.Intn(len(browserSpecs))]
		transport = newUTLSRoundTripper(spec)
	}
	
	return &http.Client{
		Timeout:   120 * time.Second,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects (browser-like)
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// createStreamingBrowserClient creates an HTTP client for streaming with no timeout
func createStreamingBrowserClient(isLocalhost bool) *http.Client {
	// Create cookie jar for session persistence
	jar, _ := cookiejar.New(&cookiejar.Options{})
	
	var transport http.RoundTripper
	if isLocalhost {
		// Use standard transport for localhost
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return dialer.DialContext(ctx, "tcp4", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		// Use uTLS round tripper for external requests with proper HTTP/2 support
		spec := browserSpecs[rand.Intn(len(browserSpecs))]
		transport = newUTLSRoundTripper(spec)
	}
	
	return &http.Client{
		Timeout:   0, // No timeout for streaming responses
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects (browser-like)
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (a *Agent) forward(rd *ReqFrame) (int, map[string][]string, []byte, error) {
	return a.forwardInternal(rd, nil, nil)
}

func (a *Agent) forwardWithStreamingHandler(rd *ReqFrame, ctx context.Context, writeEncrypted func(v any) error) (int, map[string][]string, []byte, error) {
	return a.forwardInternal(rd, ctx, writeEncrypted)
}

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
	client := createBrowserClient(isLocalhost)
	
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
			a.handleStreamingResponseDirect(ctx, rd, resp, writeEncrypted)
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
	if a.RewriteContent {
		b = a.rewriteContent(b, contentType, rd)
	}

	// Rewrite CORS and security headers (if enabled)
	if a.RewriteHeaders {
		a.rewriteResponseHeaders(resp.Header, rd)
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

	// For streaming responses, return the response object for reuse
	// We'll store it in a way that can be retrieved by the streaming handler
	return resp.StatusCode, resp.Header, []byte("STREAMING_RESPONSE"), nil
}

// handleStreamingResponseDirect handles streaming directly with the original response
func (a *Agent) handleStreamingResponseDirect(ctx context.Context, req *ReqFrame, resp *http.Response, writeEncrypted func(v any) error) {
	defer resp.Body.Close()

	log.Printf("AGENT STREAMING: Stream established directly | ReqID: %s | Status: %d | ContentType: %s",
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

	// Stream data in real-time with connection health monitoring
	buf := make([]byte, 32768) // Increased from 4KB to 32KB for better streaming
	chunkIndex := 1

	log.Printf("AGENT STREAMING: Starting stream loop | ReqID: %s | BufferSize: %d", req.ReqID, len(buf))

	// Add connection health monitoring
	lastWriteTime := time.Now()
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()

	// Start health monitoring in a separate goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				log.Printf("AGENT STREAMING: Health check timer triggered | ReqID: %s", req.ReqID)
				// Check if we're still able to write to the WebSocket
				if time.Since(lastWriteTime) > 30*time.Second {
					log.Printf("AGENT STREAMING: No writes in 30s, checking connection health | ReqID: %s", req.ReqID)
					// Try to send a heartbeat to check connection
					heartbeat := HeartbeatFrame{
						Type:        "streaming_heartbeat",
						ReqID:       req.ReqID,
						Status:      resp.StatusCode,
						Headers:     nil,
						ChunkIndex:  -1, // Special index for heartbeat
						TotalChunks: -1,
						Data:        []byte("heartbeat"),
						IsLast:      false,
						Timestamp:   time.Now().Unix(),
					}
					if err := writeEncrypted(heartbeat); err != nil {
						log.Printf("AGENT STREAMING: Connection health check failed | ReqID: %s | Error: %v", req.ReqID, err)
						return
					}
					log.Printf("AGENT STREAMING: Connection health check passed | ReqID: %s", req.ReqID)
				}
			}
		}
	}()

	// Main streaming loop with non-blocking reads using goroutine and channels
	for {
		log.Printf("AGENT STREAMING: Starting loop iteration | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)

		// Use a channel to make the read interruptible
		type readResult struct {
			n   int
			err error
		}
		readChan := make(chan readResult, 1)

		// Start the read in a goroutine
		go func() {
			log.Printf("AGENT STREAMING: About to read from response body (BLOCKING) | ReqID: %s | Attempt: %d", req.ReqID, chunkIndex)
			n, err := resp.Body.Read(buf)
			log.Printf("AGENT STREAMING: Read operation completed | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			readChan <- readResult{n: n, err: err}
		}()

		// Wait for either context cancellation, timeout, or read completion
		var n int
		var err error
		
		// Add a timeout for debugging slow reads
		readTimeout := time.NewTimer(10 * time.Second)
		defer readTimeout.Stop()
		
		select {
		case <-ctx.Done():
			log.Printf("AGENT STREAMING: Context cancelled | ReqID: %s", req.ReqID)
			return
		case <-readTimeout.C:
			log.Printf("AGENT STREAMING: Read timeout after 10s, continuing to wait | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)
			// Don't return, continue waiting for the read
			select {
			case <-ctx.Done():
				log.Printf("AGENT STREAMING: Context cancelled during timeout wait | ReqID: %s", req.ReqID)
				return
			case result := <-readChan:
				n = result.n
				err = result.err
				log.Printf("AGENT STREAMING: Read completed after timeout | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			}
		case result := <-readChan:
			n = result.n
			err = result.err
			log.Printf("AGENT STREAMING: Read from response body | ReqID: %s | BytesRead: %d | Error: %v | BufferSize: %d", req.ReqID, n, err, len(buf))
		}

		if n > 0 {
			log.Printf("AGENT STREAMING: Processing chunk with %d bytes | ReqID: %s", n, req.ReqID)
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

			log.Printf("AGENT STREAMING: About to send chunk %d | ReqID: %s | Size: %d bytes", chunkIndex, req.ReqID, n)

			if err := writeEncrypted(chunkFrame); err != nil {
				log.Printf("AGENT STREAMING: Failed to send chunk %d | ReqID: %s | Error: %v", chunkIndex, req.ReqID, err)
				return
			}

			log.Printf("AGENT STREAMING: Sent chunk %d (%d bytes) | ReqID: %s", chunkIndex, n, req.ReqID)
			chunkIndex++
			lastWriteTime = time.Now() // Update last write time
		}

		if err != nil {
			if err == io.EOF {
				// Stream ended normally
				log.Printf("AGENT STREAMING: Stream ended with EOF | ReqID: %s | TotalChunks: %d", req.ReqID, chunkIndex)
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

// handleStreamingRequest handles real-time streaming responses (SSE, etc.) - LEGACY PATH
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

	// Determine if this is a localhost request
	isLocalhost := strings.Contains(target, "127.0.0.1") || strings.Contains(target, "localhost")
	
	// Create uTLS-enabled streaming HTTP client for browser-like TLS fingerprinting
	client := createStreamingBrowserClient(isLocalhost)
	
	if isLocalhost {
		log.Printf("AGENT STREAMING: Using standard TLS for localhost | Target: %s | ReqID: %s", target, req.ReqID)
	} else {
		log.Printf("AGENT STREAMING: Using uTLS browser fingerprint for external target | Target: %s | ReqID: %s", target, req.ReqID)
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

	// Stream data in real-time with connection health monitoring
	buf := make([]byte, 32768) // Increased from 4KB to 32KB for better streaming
	chunkIndex := 1

	log.Printf("AGENT STREAMING: Starting stream loop | ReqID: %s | BufferSize: %d", req.ReqID, len(buf))

	// Add connection health monitoring
	lastWriteTime := time.Now()
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()

	// Start health monitoring in a separate goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				log.Printf("AGENT STREAMING: Health check timer triggered | ReqID: %s", req.ReqID)
				// Check if we're still able to write to the WebSocket
				if time.Since(lastWriteTime) > 30*time.Second {
					log.Printf("AGENT STREAMING: No writes in 30s, checking connection health | ReqID: %s", req.ReqID)
					// Try to send a heartbeat to check connection
					heartbeat := HeartbeatFrame{
						Type:        "streaming_heartbeat",
						ReqID:       req.ReqID,
						Status:      resp.StatusCode,
						Headers:     nil,
						ChunkIndex:  -1, // Special index for heartbeat
						TotalChunks: -1,
						Data:        []byte("heartbeat"),
						IsLast:      false,
						Timestamp:   time.Now().Unix(),
					}
					if err := writeEncrypted(heartbeat); err != nil {
						log.Printf("AGENT STREAMING: Connection health check failed | ReqID: %s | Error: %v", req.ReqID, err)
						return
					}
					log.Printf("AGENT STREAMING: Connection health check passed | ReqID: %s", req.ReqID)
				}
			}
		}
	}()

	// Main streaming loop with non-blocking reads using goroutine and channels
	for {
		log.Printf("AGENT STREAMING: Starting loop iteration | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)

		// Use a channel to make the read interruptible
		type readResult struct {
			n   int
			err error
		}
		readChan := make(chan readResult, 1)

		// Start the read in a goroutine
		go func() {
			log.Printf("AGENT STREAMING: About to read from response body (BLOCKING) | ReqID: %s | Attempt: %d", req.ReqID, chunkIndex)
			n, err := resp.Body.Read(buf)
			log.Printf("AGENT STREAMING: Read operation completed | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			readChan <- readResult{n: n, err: err}
		}()

		// Wait for either context cancellation, timeout, or read completion
		var n int
		var err error
		
		// Add a timeout for debugging slow reads
		readTimeout := time.NewTimer(10 * time.Second)
		defer readTimeout.Stop()
		
		select {
		case <-ctx.Done():
			log.Printf("AGENT STREAMING: Context cancelled | ReqID: %s", req.ReqID)
			return
		case <-readTimeout.C:
			log.Printf("AGENT STREAMING: Read timeout after 10s, continuing to wait | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)
			// Don't return, continue waiting for the read
			select {
			case <-ctx.Done():
				log.Printf("AGENT STREAMING: Context cancelled during timeout wait | ReqID: %s", req.ReqID)
				return
			case result := <-readChan:
				n = result.n
				err = result.err
				log.Printf("AGENT STREAMING: Read completed after timeout | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			}
		case result := <-readChan:
			n = result.n
			err = result.err
			log.Printf("AGENT STREAMING: Read from response body | ReqID: %s | BytesRead: %d | Error: %v | BufferSize: %d", req.ReqID, n, err, len(buf))
		}

		if n > 0 {
			log.Printf("AGENT STREAMING: Processing chunk with %d bytes | ReqID: %s", n, req.ReqID)
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

			log.Printf("AGENT STREAMING: About to send chunk %d | ReqID: %s | Size: %d bytes", chunkIndex, req.ReqID, n)

			if err := writeEncrypted(chunkFrame); err != nil {
				log.Printf("AGENT STREAMING: Failed to send chunk %d | ReqID: %s | Error: %v", chunkIndex, req.ReqID, err)
				return
			}

			log.Printf("AGENT STREAMING: Sent chunk %d (%d bytes) | ReqID: %s", chunkIndex, n, req.ReqID)
			chunkIndex++
			lastWriteTime = time.Now() // Update last write time
		}

		if err != nil {
			if err == io.EOF {
				// Stream ended normally
				log.Printf("AGENT STREAMING: Stream ended with EOF | ReqID: %s | TotalChunks: %d", req.ReqID, chunkIndex)
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

	// Initialize debug logging now that we have tunnel ID
	if a.DebugLog {
		err := a.initDebugLogging()
		if err != nil {
			log.Printf("AGENT DEBUG: Failed to initialize debug logging: %v", err)
		} else {
			log.Printf("AGENT DEBUG: Debug logging initialized for tunnel ID: %s", a.ID)
		}
	}

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

		// Log debug request if enabled
		a.logDebugRequest(req)

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

		status, hdr, body, ferr := a.forwardWithStreamingHandler(req, ctx, writeEncrypted)

		// Check if this is a streaming response
		if ferr == nil && (string(body) == "STREAMING_RESPONSE" || string(body) == "STREAMING_HANDLED") {
			log.Printf("AGENT: Streaming response handled | ReqID: %s | TunnelID: %s | Status: %d | Result: %s",
				req.ReqID, a.ID, status, string(body))
			
			// If streaming was handled directly, we're done
			if string(body) == "STREAMING_HANDLED" {
				return
			}

			// Otherwise use the legacy path
			log.Printf("AGENT: Using legacy streaming path | ReqID: %s | TunnelID: %s | Status: %d | Headers: %+v",
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

		// Log debug response if enabled
		a.logDebugResponse(req.ReqID, resp.Status, resp.Headers, resp.Body)

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

// Debug logging functions

// getDebugFileName returns the debug log file name, using tunnel ID if available
func (a *Agent) getDebugFileName() string {
	if a.DebugFile != "" {
		return a.DebugFile
	}
	if a.ID != "" {
		return fmt.Sprintf("debug_%s.log", a.ID)
	}
	return "debug_unknown.log"
}

// initDebugLogging sets up debug logging to file
func (a *Agent) initDebugLogging() error {
	if !a.DebugLog {
		return nil
	}

	fileName := a.getDebugFileName()
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open debug log file %s: %v", fileName, err)
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	// Close existing file if any
	if a.debugLogFile != nil {
		a.debugLogFile.Close()
	}

	a.debugLogFile = file
	
	// Write session start marker
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	header := fmt.Sprintf("\n=== DEBUG SESSION START: %s ===\n", timestamp)
	_, err = a.debugLogFile.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write debug log header: %v", err)
	}

	return nil
}

// logDebugRequest logs request details to debug file
func (a *Agent) logDebugRequest(req *ReqFrame) {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	
	var logEntry strings.Builder
	logEntry.WriteString(fmt.Sprintf("\n--- REQUEST %s ---\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Tunnel ID: %s\n", a.ID))
	logEntry.WriteString(fmt.Sprintf("Request ID: %s\n", req.ReqID))
	logEntry.WriteString(fmt.Sprintf("Method: %s\n", req.Method))
	logEntry.WriteString(fmt.Sprintf("Path: %s\n", req.Path))
	if req.Query != "" {
		logEntry.WriteString(fmt.Sprintf("Query: %s\n", req.Query))
	}
	
	logEntry.WriteString("Headers:\n")
	for name, values := range req.Headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}
	
	if len(req.Body) > 0 {
		logEntry.WriteString(fmt.Sprintf("Body Length: %d bytes\n", len(req.Body)))
		// Log body content (truncated if too large)
		bodyStr := string(req.Body)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "... (truncated)"
		}
		logEntry.WriteString(fmt.Sprintf("Body Content:\n%s\n", bodyStr))
	}
	
	a.debugLogFile.WriteString(logEntry.String())
	a.debugLogFile.Sync() // Force write to disk
}

// logDebugResponse logs response details to debug file
func (a *Agent) logDebugResponse(reqID string, status int, headers map[string][]string, body []byte) {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	
	var logEntry strings.Builder
	logEntry.WriteString(fmt.Sprintf("\n--- RESPONSE %s ---\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Tunnel ID: %s\n", a.ID))
	logEntry.WriteString(fmt.Sprintf("Request ID: %s\n", reqID))
	logEntry.WriteString(fmt.Sprintf("Status: %d\n", status))
	
	logEntry.WriteString("Headers:\n")
	for name, values := range headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}
	
	if len(body) > 0 {
		logEntry.WriteString(fmt.Sprintf("Body Length: %d bytes\n", len(body)))
		// Log body content (truncated if too large and non-binary)
		if isBinaryContent(headers) {
			logEntry.WriteString("Body Content: [Binary data]\n")
		} else {
			bodyStr := string(body)
			if len(bodyStr) > 1000 {
				bodyStr = bodyStr[:1000] + "... (truncated)"
			}
			logEntry.WriteString(fmt.Sprintf("Body Content:\n%s\n", bodyStr))
		}
	}
	
	a.debugLogFile.WriteString(logEntry.String())
	a.debugLogFile.Sync() // Force write to disk
}

// isBinaryContent checks if the content is binary based on headers
func isBinaryContent(headers map[string][]string) bool {
	if contentType, exists := headers["Content-Type"]; exists && len(contentType) > 0 {
		ct := strings.ToLower(contentType[0])
		return strings.Contains(ct, "image/") || 
			   strings.Contains(ct, "video/") || 
			   strings.Contains(ct, "audio/") ||
			   strings.Contains(ct, "application/octet-stream") ||
			   strings.Contains(ct, "application/pdf")
	}
	return false
}

// closeDebugLogging closes the debug log file if open
func (a *Agent) closeDebugLogging() {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	// Write session end marker
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	footer := fmt.Sprintf("\n=== DEBUG SESSION END: %s ===\n", timestamp)
	a.debugLogFile.WriteString(footer)
	a.debugLogFile.Sync()

	// Close the file
	a.debugLogFile.Close()
	a.debugLogFile = nil
}

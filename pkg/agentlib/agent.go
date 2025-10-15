package agentlib

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// Agent represents the tunnel agent
type Agent struct {
	ServerURL       string
	LocalURL        string
	ID              string
	Secret          string
	Protocol        string
	Port            int
	CustomURL       string
	UseRedirect     bool
	DebugLog        bool
	DebugFile       string
	RewriteRulesFile string

	// All other fields are managed by the modular components
	// Connection management - handled by queue.go
	isConnected        bool
	connectionStateMu  sync.RWMutex

	// HTTP client - handled by client.go
	httpClient *http.Client

	// Request queue - handled by queue.go
	maxQueueSize      int
	queueTimeout      time.Duration
	requestQueue      []*PendingRequest
	requestQueueMu    sync.Mutex

	// Streaming responses - handled by streaming.go
	chunkedResps    map[string]*ChunkedResponse
	chunkedRespMu   sync.Mutex
	streamingResps  map[string]*http.Response
	streamingMu     sync.RWMutex

	// TCP connections - handled by tcp_handler.go
	tcpConns        map[string]net.Conn
	tcpConnsMu      sync.RWMutex
	tcpPendingData  map[string][]*TcpDataFrame // Buffer for data received before connection established
	tcpPendingMu    sync.RWMutex

	// Debug logging - handled by debug.go
	debugLogFile *os.File
	debugLogMu   sync.Mutex

	// Content rewriting - handled by rewriter.go
	rewriteConfig *RewriteConfig
}

// Run starts the agent and maintains the connection
// This is the main coordination function that delegates to modules
func (a *Agent) Run(ctx context.Context) error {
	// Initialize all modular components
	a.InitializeQueueNew()

	// Initialize TCP pending data buffer
	a.tcpPendingData = make(map[string][]*TcpDataFrame)

	// Initialize debug logging (delegated to debug.go)
	if err := a.initDebugLoggingNew(); err != nil {
		log.Printf("Failed to initialize debug logging: %v", err)
	}
	defer a.closeDebugLoggingNew()

	// Create HTTP client (delegated to client.go)
	a.httpClient = createBrowserClientNew(true) // true for localhost

	// Load rewrite configuration (delegated to rewriter.go)
	if err := a.LoadRewriteConfig(); err != nil {
		return fmt.Errorf("failed to load rewrite config: %w", err)
	}

	// Main connection loop with backoff
	backoff := time.Second
	maxBackoff := 60 * time.Second
	backoffMultiplier := 1.5

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Printf("Attempting to connect to server...")

		err := a.runOnce(ctx)
		if err == nil {
			log.Println("Connection closed gracefully")
			backoff = time.Second
			continue
		}

		// Calculate backoff (delegated to utils)
		backoff = calculateBackoffNew(err, backoff, maxBackoff, backoffMultiplier)

		log.Printf("Connection failed: %v", err)
		if backoff > 0 {
			log.Printf("Retrying in %v...", backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
}

// runOnce performs one connection attempt (coordination only)
func (a *Agent) runOnce(ctx context.Context) error {
	// Step 1: Register if needed (delegated to registration.go)
	if a.ID == "" || a.Secret == "" {
		log.Println("No credentials found, registering...")
		regResp, err := a.registerNew()
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}

		a.ID = regResp.ID
		a.Secret = regResp.Secret
		log.Printf("Registered successfully with ID: %s", maskSecretNew(a.ID))
		fmt.Println("  Public URL:", regResp.PublicURL)
		if regResp.CustomURL != "" {
			fmt.Println("  Custom URL:", regResp.CustomURL)
			if regResp.UseRedirect {
				fmt.Println("  SPA Redirection: Enabled")
			}
		}
	}

	// Step 2: Establish WebSocket connection
	wsURL := strings.Replace(a.ServerURL, "http", "ws", 1) + "/__ws__"
	query := fmt.Sprintf("id=%s&secret=%s", a.ID, a.Secret)
	wsURL += "?" + query

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		if strings.Contains(err.Error(), "401") {
			log.Println("Credentials rejected, clearing for re-registration...")
			a.ID = ""
			a.Secret = ""
		}
		return fmt.Errorf("WebSocket connection failed: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "Agent shutting down")

	log.Printf("Connected to server successfully with tunnel ID: %s", maskSecretNew(a.ID))

	// Step 3: Complete handshake (delegated to connection module)
	cipher, err := a.performHandshakeNew(ctx, conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	// Step 4: Set connection state (delegated to queue.go)
	a.setConnectionStateNew(true)
	defer a.setConnectionStateNew(false)

	// Step 5: Main message handling (delegated to message handler)
	return a.handleMessagesNew(ctx, conn, cipher)
}

// LoadRewriteConfig loads content rewriting configuration (delegation to rewriter.go)
func (a *Agent) LoadRewriteConfig() error {
	// For now, just use default config - file loading can be added to rewriter.go later
	a.rewriteConfig = a.getDefaultRewriteConfig()
	return nil
}
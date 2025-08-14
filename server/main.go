package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	crypto "tunnel.local/crypto"

	"github.com/google/uuid"
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
	Type    string              `json:"type"` // "req"
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type RespFrame struct {
	Type    string              `json:"type"` // "resp"
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// ChunkedRespFrame represents a chunked response for large files
type ChunkedRespFrame struct {
	Type        string              `json:"type"` // "chunked_resp"
	ReqID       string              `json:"req_id"`
	Status      int                 `json:"status"`  // Only set in first chunk
	Headers     map[string][]string `json:"headers"` // Only set in first chunk
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

type agentConn struct {
	id          string
	secret      string
	ws          *websocket.Conn
	cipher      *crypto.StreamCipher
	connectedAt time.Time

	writeMu sync.Mutex

	// reqID -> channel to deliver response (for HTTP)
	respMu  sync.Mutex
	waiters map[string]chan *RespFrame

	// TCP connection management
	tcpConnsMu sync.Mutex
	tcpConns   map[string]*TcpConn // connID -> TcpConn

	// Chunked response management
	chunkedMu        sync.Mutex
	chunkedResponses map[string]*ChunkedResponse // reqID -> ChunkedResponse

	// Connection health monitoring
	lastPong time.Time
	pingMu   sync.RWMutex
}

// ChunkedResponse tracks assembly of chunked responses
type ChunkedResponse struct {
	ReqID       string
	Status      int
	Headers     map[string][]string
	Chunks      map[int][]byte // chunkIndex -> data
	TotalChunks int
	Received    int
	LastSeen    time.Time
}

// TcpConn represents an active TCP connection through the tunnel
type TcpConn struct {
	id      string
	dataCh  chan []byte
	closeCh chan string
	closed  bool
	closeMu sync.Mutex
}

// ClientFingerprint represents comprehensive client identification
type ClientFingerprint struct {
	// Core identification
	ClientIP      string
	UserAgent     string
	SessionCookie string

	// Authentication signals
	Authorization string            // Hashed authorization header
	AuthCookies   map[string]string // Hashed auth-related cookies
	SessionTokens map[string]string // Hashed custom session headers

	// Browser fingerprinting
	AcceptLanguage string
	AcceptEncoding string
	AcceptCharset  string
	DNT            string // Do Not Track

	// Network & Infrastructure
	XForwardedFor  string
	XRealIP        string
	XClientIP      string
	CFConnectingIP string // Cloudflare
	XOriginalHost  string

	// Application-specific
	Origin  string
	Referer string
	Host    string

	// Browser capabilities
	Connection   string
	CacheControl string
	Pragma       string

	// Framework and device info
	CustomHeaders map[string]string

	// Computed fingerprint
	FingerprintHash string
	Confidence      float64
	CreatedAt       time.Time
}

// ClientSession tracks a client's tunnel mapping history
type ClientSession struct {
	ID             string
	Fingerprint    *ClientFingerprint
	LastSeen       time.Time
	TunnelMappings map[string]int     // tunnelID -> usage_count
	SuccessRate    map[string]float64 // tunnelID -> success_rate
	Confidence     float64            // Overall routing confidence
}

// ClientTracker manages client sessions and tunnel mappings
type ClientTracker struct {
	// Primary tracking
	clientSessions map[string]*ClientSession // clientKey -> session
	ipMappings     map[string][]string       // clientIP -> clientKeys
	tunnelClients  map[string][]string       // tunnelID -> clientKeys

	// Performance optimization
	recentMappings map[string]string // clientKey -> tunnelID (LRU-like)

	// Configuration
	maxSessions     int
	sessionTTL      time.Duration
	cleanupInterval time.Duration

	// Thread safety
	mu sync.RWMutex
}

// FingerprintConfig holds configuration for fingerprint extraction
type FingerprintConfig struct {
	// Header priorities
	AuthHeaderPriority    []string
	SessionCookiePatterns []string
	SessionHeaderPatterns []string
	IPHeaderPriority      []string

	// Confidence weights
	AuthWeight    float64
	SessionWeight float64
	IPWeight      float64
	BrowserWeight float64

	// Privacy settings
	HashSensitiveData bool
	MaxFingerprintAge time.Duration
}

func (a *agentConn) writeEncrypted(ctx context.Context, v any) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	// Marshal to JSON
	jsonData := mustJSON(v)

	// Encrypt the data
	encryptedData, err := a.cipher.Encrypt(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Send as binary WebSocket message
	return a.ws.Write(ctx, websocket.MessageBinary, encryptedData)
}

func (a *agentConn) write(ctx context.Context, v any) error {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	return a.ws.Write(ctx, websocket.MessageText, mustJSON(v))
}

func (a *agentConn) registerWaiter(reqID string, ch chan *RespFrame) {
	a.respMu.Lock()
	defer a.respMu.Unlock()
	a.waiters[reqID] = ch
}

func (a *agentConn) deliver(resp *RespFrame) {
	a.respMu.Lock()
	ch, ok := a.waiters[resp.ReqID]
	if ok {
		delete(a.waiters, resp.ReqID)
	}
	a.respMu.Unlock()
	if ok {
		ch <- resp
		close(ch)
	}
}

func (a *agentConn) deliverChunked(chunk *ChunkedRespFrame) {
	a.chunkedMu.Lock()
	defer a.chunkedMu.Unlock()

	reqID := chunk.ReqID

	// Get or create chunked response
	chunkedResp, exists := a.chunkedResponses[reqID]
	if !exists {
		chunkedResp = &ChunkedResponse{
			ReqID:       reqID,
			Status:      chunk.Status,
			Headers:     chunk.Headers,
			Chunks:      make(map[int][]byte),
			TotalChunks: chunk.TotalChunks,
			Received:    0,
			LastSeen:    time.Now(),
		}
		a.chunkedResponses[reqID] = chunkedResp
	}

	// Store chunk data
	chunkedResp.Chunks[chunk.ChunkIndex] = chunk.Data
	chunkedResp.Received++
	chunkedResp.LastSeen = time.Now()

	// Check if we have all chunks
	if chunkedResp.Received >= chunkedResp.TotalChunks || chunk.IsLast {
		// Assemble complete response
		var totalSize int
		for i := 0; i < chunkedResp.TotalChunks; i++ {
			if data, exists := chunkedResp.Chunks[i]; exists {
				totalSize += len(data)
			}
		}

		completeBody := make([]byte, 0, totalSize)
		for i := 0; i < chunkedResp.TotalChunks; i++ {
			if data, exists := chunkedResp.Chunks[i]; exists {
				completeBody = append(completeBody, data...)
			}
		}

		// Create complete response
		resp := &RespFrame{
			Type:    "resp",
			ReqID:   reqID,
			Status:  chunkedResp.Status,
			Headers: chunkedResp.Headers,
			Body:    completeBody,
		}

		// Clean up chunked response
		delete(a.chunkedResponses, reqID)

		// Deliver complete response
		a.respMu.Lock()
		ch, ok := a.waiters[reqID]
		if ok {
			delete(a.waiters, reqID)
		}
		a.respMu.Unlock()
		if ok {
			ch <- resp
			close(ch)
		}

		log.Printf("Assembled chunked response for %s: %d chunks, %d bytes", reqID, chunkedResp.TotalChunks, len(completeBody))
	}
}

func (a *agentConn) deliverTcpData(frame *TcpDataFrame) {
	a.tcpConnsMu.Lock()
	conn, ok := a.tcpConns[frame.ConnID]
	a.tcpConnsMu.Unlock()

	if ok && !conn.isClosed() {
		select {
		case conn.dataCh <- frame.Data:
		default:
			// Channel full, drop data
		}
	}
}

func (a *agentConn) deliverTcpDisconnect(frame *TcpDisconnectFrame) {
	a.tcpConnsMu.Lock()
	conn, ok := a.tcpConns[frame.ConnID]
	if ok {
		delete(a.tcpConns, frame.ConnID)
	}
	a.tcpConnsMu.Unlock()

	if ok {
		conn.close(frame.Reason)
	}
}

func (tc *TcpConn) isClosed() bool {
	tc.closeMu.Lock()
	defer tc.closeMu.Unlock()
	return tc.closed
}

func (tc *TcpConn) close(reason string) {
	tc.closeMu.Lock()
	defer tc.closeMu.Unlock()
	if !tc.closed {
		tc.closed = true
		select {
		case tc.closeCh <- reason:
		default:
		}
		close(tc.dataCh)
		close(tc.closeCh)
	}
}

// ---- tunnel metadata ----

type TunnelInfo struct {
	Secret   string    `json:"secret"`
	Protocol string    `json:"protocol"` // "http" or "tcp"
	Port     int       `json:"port"`     // for TCP tunnels
	Created  time.Time `json:"created"`  // when tunnel was created
}

// Cloud Run: Stateless deployment - no persistence structs needed

// ---- global in-memory stores (PoC only) ----

var (
	// tunnel id -> tunnel info
	tunnels   = map[string]*TunnelInfo{}
	tunnelsMu sync.RWMutex

	// tunnel id -> active agent connection
	agents   = map[string]*agentConn{}
	agentsMu sync.RWMutex
)

// ---- handlers ----

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

	id := uuid.NewString()
	secret := randHex(32)

	tunnelInfo := &TunnelInfo{
		Secret:   secret,
		Protocol: req.Protocol,
		Port:     req.Port,
		Created:  time.Now(),
	}

	// Register in memory (Cloud Run stateless)
	tunnelsMu.Lock()
	tunnels[id] = tunnelInfo
	tunnelsMu.Unlock()

	log.Printf("Registered tunnel %s (stateless)", id)

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
		publicURL = fmt.Sprintf("%s/tcp/%s", publicBase, id)
		tcpPort = req.Port
	} else {
		// HTTP tunnels use the existing /pub/ endpoint
		publicURL = fmt.Sprintf("%s/pub/%s", publicBase, id)
	}

	resp := RegisterResp{
		ID:        id,
		Secret:    secret,
		PublicURL: publicURL,
		Protocol:  req.Protocol,
		TcpPort:   tcpPort,
	}
	writeJSON(w, http.StatusOK, resp)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.URL.Query().Get("id")
	secret := r.URL.Query().Get("secret")
	if !validateTunnel(id, secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // fine for envs behind HTTPS (Cloud Run)
	})
	if err != nil {
		log.Printf("ws accept: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "server error")

	// Set larger message size limit to handle large assets (20MB)
	c.SetReadLimit(20 * 1024 * 1024)

	// Perform key exchange
	kx := crypto.NewKeyExchange(secret)
	cipher, err := kx.DeriveStreamCipher(true) // true = isServer
	if err != nil {
		log.Printf("failed to create cipher: %v", err)
		c.Close(websocket.StatusInternalError, "crypto error")
		return
	}

	// Send handshake with salt
	handshake := HandshakeFrame{
		Type: "handshake",
		Salt: base64.StdEncoding.EncodeToString(kx.GetSalt()),
	}
	if err := c.Write(ctx, websocket.MessageText, mustJSON(handshake)); err != nil {
		log.Printf("failed to send handshake: %v", err)
		return
	}

	// Wait for handshake response
	_, data, err := c.Read(ctx)
	if err != nil {
		log.Printf("failed to read handshake response: %v", err)
		return
	}

	var handshakeResp struct {
		Type string `json:"type"`
		ACK  bool   `json:"ack"`
	}
	if err := json.Unmarshal(data, &handshakeResp); err != nil || handshakeResp.Type != "handshake" || !handshakeResp.ACK {
		log.Printf("invalid handshake response")
		return
	}

	ac := &agentConn{
		id:               id,
		secret:           secret,
		ws:               c,
		cipher:           cipher,
		waiters:          make(map[string]chan *RespFrame),
		tcpConns:         make(map[string]*TcpConn),
		chunkedResponses: make(map[string]*ChunkedResponse),
		connectedAt:      time.Now(),
		lastPong:         time.Now(), // Initialize ping monitoring
	}

	agentsMu.Lock()
	agents[id] = ac
	agentsMu.Unlock()

	log.Printf("agent %s connected with encrypted tunnel", id)

	// Start ping monitoring goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Ping every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Send ping to agent
				pingFrame := PingFrame{
					Type:      "ping",
					Timestamp: time.Now(),
				}

				if err := ac.writeEncrypted(ctx, pingFrame); err != nil {
					log.Printf("Failed to send ping to agent %s: %v", id, err)
					return
				}

				// Check if last pong is too old
				ac.pingMu.RLock()
				lastPong := ac.lastPong
				ac.pingMu.RUnlock()

				if time.Since(lastPong) > 90*time.Second { // 3 missed pings
					log.Printf("Agent %s appears to be dead (no pong received), closing connection...", id)
					// Close the websocket connection
					ac.ws.Close(websocket.StatusGoingAway, "ping timeout")
					return
				}
			}
		}
	}()

	// reader goroutine: dispatch responses back to waiting requests
	err = agentReadLoop(ctx, ac)
	if err != nil {
		log.Printf("agent %s read loop ended: %v", id, err)
	}

	agentsMu.Lock()
	// Only delete if the agent in the map is still this one.
	// Another connection might have replaced it.
	if currentAC, ok := agents[id]; ok && currentAC == ac {
		delete(agents, id)
		log.Printf("agent %s disconnected and removed", id)
	}
	agentsMu.Unlock()

	c.Close(websocket.StatusNormalClosure, "bye")
}

func agentReadLoop(ctx context.Context, ac *agentConn) error {
	for {
		typ, data, err := ac.ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary {
			continue
		}

		// Decrypt the message
		plaintext, err := ac.cipher.Decrypt(data)
		if err != nil {
			log.Printf("failed to decrypt message from agent %s: %v", ac.id, err)
			continue
		}

		var base struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(plaintext, &base); err != nil {
			continue
		}
		switch base.Type {
		case "resp":
			var rf RespFrame
			if err := json.Unmarshal(plaintext, &rf); err != nil {
				continue
			}
			ac.deliver(&rf)
		case "chunked_resp":
			var cf ChunkedRespFrame
			if err := json.Unmarshal(plaintext, &cf); err != nil {
				continue
			}
			ac.deliverChunked(&cf)
		case "tcp_data":
			var tf TcpDataFrame
			if err := json.Unmarshal(plaintext, &tf); err != nil {
				continue
			}
			ac.deliverTcpData(&tf)
		case "tcp_disconnect":
			var tf TcpDisconnectFrame
			if err := json.Unmarshal(plaintext, &tf); err != nil {
				continue
			}
			ac.deliverTcpDisconnect(&tf)
		case "ping":
			// Respond to agent ping with pong
			var pingFrame PingFrame
			if err := json.Unmarshal(plaintext, &pingFrame); err != nil {
				continue
			}
			pongFrame := PongFrame{
				Type:      "pong",
				Timestamp: pingFrame.Timestamp,
			}
			if err := ac.writeEncrypted(context.Background(), pongFrame); err != nil {
				log.Printf("Failed to send pong to agent %s: %v", ac.id, err)
			}
		case "pong":
			// Update last pong time for connection health monitoring
			ac.pingMu.Lock()
			ac.lastPong = time.Now()
			ac.pingMu.Unlock()
		case "tunnel_info":
			// Agent is providing tunnel details for stateless reconnection
			var tunnelFrame TunnelInfoFrame
			if err := json.Unmarshal(plaintext, &tunnelFrame); err != nil {
				continue
			}

			// Recreate tunnel info for this reconnecting agent
			tunnelInfo := &TunnelInfo{
				Secret:   ac.secret,
				Protocol: tunnelFrame.Protocol,
				Port:     tunnelFrame.Port,
				Created:  time.Now(), // Mark as recreated
			}

			tunnelsMu.Lock()
			tunnels[ac.id] = tunnelInfo
			tunnelsMu.Unlock()

			log.Printf("Recreated tunnel info for reconnecting agent %s (protocol: %s, port: %d)",
				ac.id, tunnelFrame.Protocol, tunnelFrame.Port)
		default:
			// ignore
		}
	}
}

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
	}{
		ActiveConnections:   make([]agentInfo, 0, len(agents)),
		ConnectionCount:     len(agents),
		ClientTracking:      clientTracker.GetClientStats(),
		GeographicalRouting: getGeoRoutingStats(),
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

func publicHandler(w http.ResponseWriter, r *http.Request) {
	// /pub/{id}/<rest>
	path := strings.TrimPrefix(r.URL.Path, "/pub/")
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

		// Record IP-based geographical routing (NEW)
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

// ---- helpers ----

func validateTunnel(id, secret string) bool {
	if id == "" || secret == "" {
		return false
	}

	// For Cloud Run stateless deployment: validate tunnel format rather than lookup
	// Accept any tunnel with valid UUID format and non-empty secret
	if !isValidUUID(id) {
		return false
	}

	if len(secret) < 32 { // Ensure minimum secret length
		return false
	}

	// If we have the tunnel in memory (newly registered), validate normally
	tunnelsMu.RLock()
	defer tunnelsMu.RUnlock()
	if info, ok := tunnels[id]; ok {
		return info.Secret == secret
	}

	// For reconnecting agents after server restart: accept valid-looking credentials
	// This allows agents to reconnect with their existing tunnels
	log.Printf("Accepting reconnecting tunnel %s (stateless validation)", id)
	return true
}

func isValidUUID(id string) bool {
	// Basic UUID format validation (8-4-4-4-12 hex digits)
	if len(id) != 36 {
		return false
	}

	expected := []int{8, 4, 4, 4, 12}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		return false
	}

	for i, part := range parts {
		if len(part) != expected[i] {
			return false
		}
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}

	return true
}

func getTunnelInfo(id string) *TunnelInfo {
	tunnelsMu.RLock()
	defer tunnelsMu.RUnlock()
	return tunnels[id]
}

// Cloud Run: No tunnel persistence needed - removed file-based storage functions

func getAgent(id string) *agentConn {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	return agents[id]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func tcpHandler(w http.ResponseWriter, r *http.Request) {
	// Extract tunnel ID from path: /tcp/{id}
	path := strings.TrimPrefix(r.URL.Path, "/tcp/")
	if path == "" {
		http.Error(w, "missing tunnel id", http.StatusBadRequest)
		return
	}

	id := path
	ac := getAgent(id)
	if ac == nil {
		http.Error(w, "agent not connected", http.StatusBadGateway)
		return
	}

	// Verify this is a TCP tunnel
	tunnelInfo := getTunnelInfo(id)
	if tunnelInfo == nil || tunnelInfo.Protocol != "tcp" {
		http.Error(w, "not a TCP tunnel", http.StatusBadRequest)
		return
	}

	// Upgrade to WebSocket for TCP streaming
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("tcp websocket accept: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "server error")

	handleTcpConnection(r.Context(), c, ac, tunnelInfo.Port)
}

func handleTcpConnection(ctx context.Context, ws *websocket.Conn, ac *agentConn, port int) {
	connID := uuid.NewString()

	// Create TCP connection tracking
	tcpConn := &TcpConn{
		id:      connID,
		dataCh:  make(chan []byte, 100),
		closeCh: make(chan string, 1),
		closed:  false,
	}

	ac.tcpConnsMu.Lock()
	ac.tcpConns[connID] = tcpConn
	ac.tcpConnsMu.Unlock()

	// Send TCP connect frame to agent
	connectFrame := TcpConnectFrame{
		Type:   "tcp_connect",
		ConnID: connID,
		Port:   port,
	}

	if err := ac.writeEncrypted(ctx, connectFrame); err != nil {
		log.Printf("failed to send tcp connect: %v", err)
		return
	}

	// Handle bidirectional data flow
	go func() {
		// Read from WebSocket and send to agent
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				// Send disconnect to agent
				disconnectFrame := TcpDisconnectFrame{
					Type:   "tcp_disconnect",
					ConnID: connID,
					Reason: "client disconnected",
				}
				ac.writeEncrypted(ctx, disconnectFrame)
				return
			}

			// Forward data to agent
			dataFrame := TcpDataFrame{
				Type:   "tcp_data",
				ConnID: connID,
				Data:   data,
			}
			if err := ac.writeEncrypted(ctx, dataFrame); err != nil {
				log.Printf("failed to send tcp data: %v", err)
				return
			}
		}
	}()

	// Read from agent and send to WebSocket
	for {
		select {
		case data, ok := <-tcpConn.dataCh:
			if !ok {
				return // Connection closed
			}
			if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
				log.Printf("failed to write to websocket: %v", err)
				return
			}
		case reason := <-tcpConn.closeCh:
			log.Printf("TCP connection %s closed: %s", connID, reason)
			ws.Close(websocket.StatusNormalClosure, reason)
			return
		case <-ctx.Done():
			return
		}
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// isAssetRequest detects if a request is for a static asset
func isAssetRequest(path string) bool {
	// Common asset path patterns
	assetPaths := []string{
		"/assets/", "/static/", "/js/", "/css/", "/images/", "/img/",
		"/fonts/", "/public/", "/_next/", "/_nuxt/", "/build/",
	}

	for _, assetPath := range assetPaths {
		if strings.HasPrefix(path, assetPath) {
			return true
		}
	}

	// Common asset file extensions
	assetExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".json", ".xml",
		".webp", ".avif", ".mp4", ".webm", ".mp3", ".wav",
	}

	pathLower := strings.ToLower(path)
	for _, ext := range assetExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}

	return false
}

// isAPIRequest detects if a request is for an API endpoint
func isAPIRequest(path string) bool {
	// Common API path patterns
	apiPaths := []string{
		"/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/v4/",
		"/graphql", "/rpc/", "/service/", "/services/",
		"/endpoint/", "/endpoints/", "/webhook/", "/webhooks/",
		"/auth/", "/oauth/", "/login", "/logout", "/signin", "/signout",
	}

	for _, apiPath := range apiPaths {
		if strings.HasPrefix(path, apiPath) || path == strings.TrimSuffix(apiPath, "/") {
			return true
		}
	}

	// Common API file patterns (JSON responses)
	if strings.HasSuffix(path, ".json") && !strings.Contains(path, "/assets/") {
		return true
	}

	return false
}

// recordClientAssetMapping stores a client->tunnel mapping for future asset requests
func recordClientAssetMapping(clientKey, tunnelID string) {
	clientAssetMu.Lock()
	defer clientAssetMu.Unlock()
	clientAssetMappings[clientKey] = tunnelID
	log.Printf("Smart routing: recorded asset mapping %s -> %s", clientKey, tunnelID)
}

// Simple geographical routing functions

// lookupIPGeoData performs a simple geographical lookup for an IP address
func lookupIPGeoData(ipAddress string) *IPGeoData {
	if !geoRoutingConfig.EnableGeoRouting || ipAddress == "" {
		return nil
	}

	// Check cache first
	ipGeoCacheMu.RLock()
	if cached, exists := ipGeoCache[ipAddress]; exists {
		// Check if cache is still valid
		if time.Since(cached.CacheTime) < geoRoutingConfig.GeoCacheTTL {
			ipGeoCacheMu.RUnlock()
			return cached
		}
	}
	ipGeoCacheMu.RUnlock()

	// For now, implement a simple country/region detection based on IP patterns
	// This is a placeholder - in production you'd use a real GeoIP database
	geoData := &IPGeoData{
		Country:   getCountryFromIP(ipAddress),
		Region:    getRegionFromIP(ipAddress),
		CacheTime: time.Now(),
	}

	// Cache the result (with size limit)
	ipGeoCacheMu.Lock()
	if len(ipGeoCache) >= geoRoutingConfig.MaxGeoCache {
		// Simple cache eviction - remove oldest entry
		var oldestIP string
		var oldestTime time.Time = time.Now()
		for ip, data := range ipGeoCache {
			if data.CacheTime.Before(oldestTime) {
				oldestTime = data.CacheTime
				oldestIP = ip
			}
		}
		if oldestIP != "" {
			delete(ipGeoCache, oldestIP)
		}
	}
	ipGeoCache[ipAddress] = geoData
	ipGeoCacheMu.Unlock()

	return geoData
}

// Simple IP-based country detection (placeholder implementation)
func getCountryFromIP(ipAddress string) string {
	// This is a very basic implementation based on IP ranges
	// In production, you would use a proper GeoIP database like GeoLite2

	if strings.HasPrefix(ipAddress, "127.") || strings.HasPrefix(ipAddress, "::1") {
		return "LOCAL"
	}

	// US IP ranges (simplified examples)
	if strings.HasPrefix(ipAddress, "8.") || strings.HasPrefix(ipAddress, "4.") {
		return "US"
	}

	// European IP ranges (simplified examples)
	if strings.HasPrefix(ipAddress, "85.") || strings.HasPrefix(ipAddress, "91.") {
		return "EU"
	}

	// Asian IP ranges (simplified examples)
	if strings.HasPrefix(ipAddress, "202.") || strings.HasPrefix(ipAddress, "203.") {
		return "AS"
	}

	// Default to unknown
	return "UNKNOWN"
}

// Simple IP-based region detection (placeholder implementation)
func getRegionFromIP(ipAddress string) string {
	country := getCountryFromIP(ipAddress)

	switch country {
	case "US":
		// Very basic US region detection based on IP
		if strings.HasPrefix(ipAddress, "8.8.") {
			return "US-WEST"
		}
		return "US-EAST"
	case "EU":
		return "EU-CENTRAL"
	case "AS":
		return "AS-PACIFIC"
	default:
		return country + "-DEFAULT"
	}
}

// recordIPTunnelMapping records successful IP -> tunnel mapping
func recordIPTunnelMapping(ipAddress, tunnelID string) {
	if !geoRoutingConfig.EnableGeoRouting || ipAddress == "" || tunnelID == "" {
		return
	}

	ipTunnelMu.Lock()
	defer ipTunnelMu.Unlock()

	// Check size limit
	if len(ipTunnelMap) >= geoRoutingConfig.MaxIPMappings {
		// Simple cleanup - remove entries older than TTL
		now := time.Now()
		for ip, mapping := range ipTunnelMap {
			if now.Sub(mapping.LastSuccess) > geoRoutingConfig.IPMappingTTL {
				delete(ipTunnelMap, ip)
			}
		}
	}

	if existing, exists := ipTunnelMap[ipAddress]; exists {
		// Update existing mapping
		existing.LastTunnelID = tunnelID
		existing.LastSuccess = time.Now()
		existing.UsageCount++

		// Update success rate using exponential moving average
		existing.SuccessRate = existing.SuccessRate*0.9 + 1.0*0.1
	} else {
		// Create new mapping
		ipTunnelMap[ipAddress] = &IPTunnelMapping{
			IPAddress:    ipAddress,
			LastTunnelID: tunnelID,
			LastSuccess:  time.Now(),
			UsageCount:   1,
			SuccessRate:  1.0,
		}
	}

	// Also update geographical preferences
	updateGeoTunnelPreference(ipAddress, tunnelID)

	log.Printf("Smart routing: recorded IP tunnel mapping %s -> %s", ipAddress, tunnelID)
}

// updateGeoTunnelPreference updates tunnel preferences for geographical regions
func updateGeoTunnelPreference(ipAddress, tunnelID string) {
	geoData := lookupIPGeoData(ipAddress)
	if geoData == nil {
		return
	}

	geoKey := geoData.Country + "_" + geoData.Region

	geoTunnelMu.Lock()
	defer geoTunnelMu.Unlock()

	if existing, exists := geoTunnelPrefs[geoKey]; exists {
		// Update existing preference
		existing.TunnelID = tunnelID
		existing.UsageCount++
		existing.LastUsed = time.Now()
		existing.SuccessRate = existing.SuccessRate*0.9 + 1.0*0.1
	} else {
		// Create new preference
		geoTunnelPrefs[geoKey] = &GeoTunnelPreference{
			TunnelID:    tunnelID,
			UsageCount:  1,
			SuccessRate: 1.0,
			LastUsed:    time.Now(),
		}
	}

	log.Printf("Smart routing: updated geo preference %s -> %s", geoKey, tunnelID)
}

// getIPTunnelMapping retrieves the preferred tunnel for an IP address
func getIPTunnelMapping(ipAddress string) string {
	if !geoRoutingConfig.EnableGeoRouting || ipAddress == "" {
		return ""
	}

	ipTunnelMu.RLock()
	defer ipTunnelMu.RUnlock()

	if mapping, exists := ipTunnelMap[ipAddress]; exists {
		// Check if mapping is still valid
		if time.Since(mapping.LastSuccess) <= geoRoutingConfig.IPMappingTTL {
			return mapping.LastTunnelID
		}
	}

	return ""
}

// getGeoTunnelPreference retrieves the preferred tunnel for a geographical region
func getGeoTunnelPreference(ipAddress string) string {
	if !geoRoutingConfig.EnableGeoRouting || ipAddress == "" {
		return ""
	}

	geoData := lookupIPGeoData(ipAddress)
	if geoData == nil {
		return ""
	}

	geoKey := geoData.Country + "_" + geoData.Region

	geoTunnelMu.RLock()
	defer geoTunnelMu.RUnlock()

	if pref, exists := geoTunnelPrefs[geoKey]; exists {
		// Check if preference is recent and has good success rate
		if time.Since(pref.LastUsed) <= geoRoutingConfig.GeoCacheTTL && pref.SuccessRate > 0.5 {
			return pref.TunnelID
		}
	}

	return ""
}

// getGeoRoutingStats returns statistics about geographical routing
func getGeoRoutingStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":     geoRoutingConfig.EnableGeoRouting,
		"cache_ttl":   geoRoutingConfig.GeoCacheTTL.String(),
		"mapping_ttl": geoRoutingConfig.IPMappingTTL.String(),
	}

	if !geoRoutingConfig.EnableGeoRouting {
		return stats
	}

	// Get IP mapping stats
	ipTunnelMu.RLock()
	ipMappingCount := len(ipTunnelMap)
	ipStats := make(map[string]interface{})
	countryStats := make(map[string]int)

	for _, mapping := range ipTunnelMap {
		geoData := lookupIPGeoData(mapping.IPAddress)
		if geoData != nil {
			countryStats[geoData.Country]++
		}
	}
	ipTunnelMu.RUnlock()

	ipStats["total_mappings"] = ipMappingCount
	ipStats["countries"] = countryStats

	// Get geo cache stats
	ipGeoCacheMu.RLock()
	geoCacheCount := len(ipGeoCache)
	ipGeoCacheMu.RUnlock()

	// Get geo tunnel preferences
	geoTunnelMu.RLock()
	geoPrefsCount := len(geoTunnelPrefs)
	geoRegions := make([]string, 0, len(geoTunnelPrefs))
	for geoKey := range geoTunnelPrefs {
		geoRegions = append(geoRegions, geoKey)
	}
	geoTunnelMu.RUnlock()

	stats["ip_mappings"] = ipStats
	stats["geo_cache_size"] = geoCacheCount
	stats["geo_preferences"] = map[string]interface{}{
		"count":   geoPrefsCount,
		"regions": geoRegions,
	}

	return stats
}

// getClientAssetMapping retrieves the tunnel ID for a client's asset requests
func getClientAssetMapping(clientKey string) string {
	clientAssetMu.RLock()
	defer clientAssetMu.RUnlock()
	return clientAssetMappings[clientKey]
}

// getClientAssetMappingWithFallback tries multiple strategies to find a tunnel mapping
func getClientAssetMappingWithFallback(r *http.Request, clientKey string) string {
	// Strategy 1: Direct client key mapping
	if tunnelID := getClientAssetMapping(clientKey); tunnelID != "" {
		return tunnelID
	}

	// Strategy 2: Try IP-based fallback
	clientIP := extractRealClientIP(r)
	if clientIP != "" {
		clientAssetMu.RLock()
		for key, tunnelID := range clientAssetMappings {
			if strings.Contains(key, clientIP) {
				clientAssetMu.RUnlock()
				log.Printf("Smart routing: found IP-based mapping %s -> %s for client %s", clientIP, tunnelID, clientKey)
				return tunnelID
			}
		}
		clientAssetMu.RUnlock()
	}

	// Strategy 3: Try User-Agent based fallback
	userAgent := r.Header.Get("User-Agent")
	if userAgent != "" {
		hashedUA := hashSensitive(userAgent)
		clientAssetMu.RLock()
		for key, tunnelID := range clientAssetMappings {
			if strings.Contains(key, hashedUA) {
				clientAssetMu.RUnlock()
				log.Printf("Smart routing: found UA-based mapping %s -> %s for client %s", hashedUA[:8], tunnelID, clientKey)
				return tunnelID
			}
		}
		clientAssetMu.RUnlock()
	}

	return ""
}

// Asset mapping cache for performance optimization
var (
	assetCache   = make(map[string]string) // assetPath -> tunnelID
	assetCacheMu sync.RWMutex

	// Enhanced asset tracking
	clientAssetMappings = make(map[string]string) // clientKey -> tunnelID
	clientAssetMu       sync.RWMutex
)

// Simple IP-based geographical routing structures
type IPGeoData struct {
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	CacheTime time.Time `json:"cache_time"`
}

type IPTunnelMapping struct {
	IPAddress    string    `json:"ip_address"`
	LastTunnelID string    `json:"last_tunnel_id"`
	LastSuccess  time.Time `json:"last_success"`
	UsageCount   int       `json:"usage_count"`
	SuccessRate  float64   `json:"success_rate"`
}

type GeoTunnelPreference struct {
	TunnelID    string    `json:"tunnel_id"`
	UsageCount  int       `json:"usage_count"`
	SuccessRate float64   `json:"success_rate"`
	LastUsed    time.Time `json:"last_used"`
}

// Fast in-memory geographical routing stores
var (
	ipGeoCache     = make(map[string]*IPGeoData)           // IP -> geo data
	ipTunnelMap    = make(map[string]*IPTunnelMapping)     // IP -> tunnel mapping
	geoTunnelPrefs = make(map[string]*GeoTunnelPreference) // country_region -> preferred tunnel
	ipGeoCacheMu   sync.RWMutex
	ipTunnelMu     sync.RWMutex
	geoTunnelMu    sync.RWMutex

	// Configuration
	geoRoutingConfig = struct {
		EnableGeoRouting bool
		GeoCacheTTL      time.Duration
		IPMappingTTL     time.Duration
		MaxGeoCache      int
		MaxIPMappings    int
	}{
		EnableGeoRouting: true,
		GeoCacheTTL:      24 * time.Hour,     // Cache geo data for 24 hours
		IPMappingTTL:     7 * 24 * time.Hour, // Keep IP mappings for 7 days
		MaxGeoCache:      10000,              // Max cached geo lookups
		MaxIPMappings:    50000,              // Max IP tunnel mappings
	}
)

// Client tracking and fingerprinting
var (
	clientTracker = &ClientTracker{
		clientSessions:  make(map[string]*ClientSession),
		ipMappings:      make(map[string][]string),
		tunnelClients:   make(map[string][]string),
		recentMappings:  make(map[string]string),
		maxSessions:     10000,
		sessionTTL:      30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}

	fingerprintConfig = &FingerprintConfig{
		AuthHeaderPriority: []string{
			"Authorization", "X-Auth-Token", "X-API-Key",
			"X-Access-Token", "X-Session-Token",
		},
		SessionCookiePatterns: []string{
			"sessionid", "session_id", "SESSIONID",
			"jsessionid", "JSESSIONID", "connect.sid",
			"token", "auth_token", "authtoken",
			"jwt", "access_token", "_session", "_token",
		},
		SessionHeaderPatterns: []string{
			"X-Session-ID", "X-User-Token", "X-Client-ID",
			"X-Request-ID", "X-Correlation-ID", "X-Device-ID",
		},
		IPHeaderPriority: []string{
			"CF-Connecting-IP", "True-Client-IP", "X-Real-IP",
			"X-Forwarded-For", "X-Client-IP", "X-Cluster-Client-IP",
		},
		AuthWeight:        0.4,
		SessionWeight:     0.3,
		IPWeight:          0.2,
		BrowserWeight:     0.15,
		HashSensitiveData: true,
		MaxFingerprintAge: 24 * time.Hour,
	}
)

// Privacy-conscious hashing for sensitive data
func hashSensitive(data string) string {
	if !fingerprintConfig.HashSensitiveData || data == "" {
		return data
	}
	h := sha256.New()
	h.Write([]byte(data))
	// Use first 16 characters for balance of uniqueness vs privacy
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Generate stable hash from components
func generateStableHash(components []string) string {
	// Sort components for consistent ordering
	sort.Strings(components)
	combined := strings.Join(components, "|")

	h := sha256.New()
	h.Write([]byte(combined))
	return hex.EncodeToString(h.Sum(nil))[:20]
}

// Extract real client IP from various proxy headers
func extractRealClientIP(r *http.Request) string {
	if r == nil || r.Header == nil {
		return ""
	}

	// Check configured IP headers in priority order
	for _, header := range fingerprintConfig.IPHeaderPriority {
		if ip := r.Header.Get(header); ip != "" {
			// Handle X-Forwarded-For chain (client, proxy1, proxy2)
			if header == "X-Forwarded-For" {
				ips := strings.Split(ip, ",")
				if len(ips) > 0 {
					return strings.TrimSpace(ips[0])
				}
			}
			return strings.TrimSpace(ip)
		}
	}

	// Fallback to remote address
	if r.RemoteAddr != "" {
		if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return ip
		}
		return r.RemoteAddr
	}

	return ""
}

// Check if cookie name matches session patterns
func isSessionCookie(name string) bool {
	nameLower := strings.ToLower(name)
	for _, pattern := range fingerprintConfig.SessionCookiePatterns {
		patternLower := strings.ToLower(pattern)
		// Exact match or starts/ends with pattern for better precision
		if nameLower == patternLower ||
			strings.HasPrefix(nameLower, patternLower) ||
			strings.HasSuffix(nameLower, patternLower) ||
			strings.Contains(nameLower, patternLower+"_") ||
			strings.Contains(nameLower, "_"+patternLower) {
			// Exclude CSRF tokens which contain "token" but aren't session cookies
			if strings.Contains(nameLower, "csrf") {
				return false
			}
			return true
		}
	}
	return false
}

// Check if cookie name matches auth patterns
func isAuthCookie(name string) bool {
	authPatterns := []string{
		"auth", "login", "user", "uid",
		"oauth", "bearer", "credential",
		"identity", "principal",
	}

	nameLower := strings.ToLower(name)
	for _, pattern := range authPatterns {
		if strings.Contains(nameLower, pattern) {
			return true
		}
	}
	return false
}

// Check if header name matches session header patterns
func isSessionHeader(name string) bool {
	for _, pattern := range fingerprintConfig.SessionHeaderPatterns {
		if strings.EqualFold(name, pattern) {
			return true
		}
	}
	return false
}

// Extract primary authentication-based fingerprint (highest confidence)
func extractPrimaryFingerprint(r *http.Request) *ClientFingerprint {
	fp := &ClientFingerprint{
		AuthCookies:   make(map[string]string),
		SessionTokens: make(map[string]string),
		CustomHeaders: make(map[string]string),
		CreatedAt:     time.Now(),
	}

	// Authentication headers (highest confidence)
	for _, header := range fingerprintConfig.AuthHeaderPriority {
		if auth := r.Header.Get(header); auth != "" {
			fp.Authorization = hashSensitive(auth)
			fp.Confidence += fingerprintConfig.AuthWeight
			break // Use first found auth header
		}
	}

	// Session cookies (high confidence)
	for _, cookie := range r.Cookies() {
		if isSessionCookie(cookie.Name) && fp.SessionCookie == "" {
			fp.SessionCookie = cookie.Value
			fp.Confidence += fingerprintConfig.SessionWeight
		}
		if isAuthCookie(cookie.Name) {
			fp.AuthCookies[cookie.Name] = hashSensitive(cookie.Value)
			fp.Confidence += 0.1
		}
	}

	// Custom session headers
	for headerName, headerValues := range r.Header {
		if isSessionHeader(headerName) && len(headerValues) > 0 {
			fp.SessionTokens[headerName] = hashSensitive(headerValues[0])
			fp.Confidence += 0.15
		}
	}

	return fp
}

// Add secondary browser and network fingerprinting
func addSecondaryFingerprint(fp *ClientFingerprint, r *http.Request) {
	// Network identification
	fp.ClientIP = extractRealClientIP(r)
	if fp.ClientIP != "" {
		fp.Confidence += fingerprintConfig.IPWeight
	}

	// Browser fingerprinting
	fp.UserAgent = r.Header.Get("User-Agent")
	fp.AcceptLanguage = r.Header.Get("Accept-Language")
	fp.AcceptEncoding = r.Header.Get("Accept-Encoding")
	fp.AcceptCharset = r.Header.Get("Accept-Charset")
	fp.DNT = r.Header.Get("DNT")

	if fp.UserAgent != "" && fp.AcceptLanguage != "" {
		fp.Confidence += fingerprintConfig.BrowserWeight
	}

	// Network headers
	fp.XForwardedFor = r.Header.Get("X-Forwarded-For")
	fp.XRealIP = r.Header.Get("X-Real-IP")
	fp.XClientIP = r.Header.Get("X-Client-IP")
	fp.CFConnectingIP = r.Header.Get("CF-Connecting-IP")
	fp.XOriginalHost = r.Header.Get("X-Original-Host")

	// Application headers
	fp.Origin = r.Header.Get("Origin")
	fp.Referer = r.Header.Get("Referer")
	fp.Host = r.Header.Get("Host")

	// Browser capabilities
	fp.Connection = r.Header.Get("Connection")
	fp.CacheControl = r.Header.Get("Cache-Control")
	fp.Pragma = r.Header.Get("Pragma")
}

// Extract framework-specific headers
func extractFrameworkHeaders(r *http.Request) map[string]string {
	frameworkHeaders := make(map[string]string)

	if r == nil || r.Header == nil {
		return frameworkHeaders
	}

	// React/Next.js
	if nextData := r.Header.Get("X-NextJS-Data"); nextData != "" {
		frameworkHeaders["nextjs"] = nextData
	}

	// Angular
	if ngVersion := r.Header.Get("X-Angular-Version"); ngVersion != "" {
		frameworkHeaders["angular"] = ngVersion
	}

	// Vue.js
	if vueDevtools := r.Header.Get("X-Vue-Devtools"); vueDevtools != "" {
		frameworkHeaders["vue"] = vueDevtools
	}

	// CSRF tokens
	if csrfToken := r.Header.Get("X-CSRF-Token"); csrfToken != "" {
		frameworkHeaders["csrf"] = hashSensitive(csrfToken)
	}

	// API versioning
	if apiVersion := r.Header.Get("X-API-Version"); apiVersion != "" {
		frameworkHeaders["api_version"] = apiVersion
	}

	// Client Hints API
	if platform := r.Header.Get("Sec-CH-UA-Platform"); platform != "" {
		frameworkHeaders["platform"] = platform
	}

	if ua := r.Header.Get("Sec-CH-UA"); ua != "" {
		frameworkHeaders["browser"] = ua
	}

	// Device and network hints
	if memory := r.Header.Get("Device-Memory"); memory != "" {
		frameworkHeaders["memory"] = memory
	}

	if network := r.Header.Get("Downlink"); network != "" {
		frameworkHeaders["network"] = network
	}

	return frameworkHeaders
}

// Generate composite fingerprint hash
func generateCompositeFingerprint(fp *ClientFingerprint) {
	var components []string

	// Priority order for fingerprint generation
	if fp.Authorization != "" {
		components = append(components, "auth:"+fp.Authorization)
	}

	if fp.SessionCookie != "" {
		components = append(components, "session:"+fp.SessionCookie)
	}

	for name, value := range fp.SessionTokens {
		components = append(components, "token:"+name+":"+value)
	}

	if fp.ClientIP != "" {
		components = append(components, "ip:"+fp.ClientIP)
	}

	if fp.UserAgent != "" {
		components = append(components, "ua:"+hashSensitive(fp.UserAgent))
	}

	if fp.AcceptLanguage != "" {
		components = append(components, "lang:"+fp.AcceptLanguage)
	}

	// Add framework-specific data
	for key, value := range fp.CustomHeaders {
		components = append(components, "custom:"+key+":"+value)
	}

	// Generate stable hash
	fp.FingerprintHash = generateStableHash(components)
}

// Generate hierarchical client key with fallback strategy
func generateClientKey(r *http.Request) string {
	fp := extractPrimaryFingerprint(r)
	addSecondaryFingerprint(fp, r)
	fp.CustomHeaders = extractFrameworkHeaders(r)
	generateCompositeFingerprint(fp)

	// Create hierarchical client keys for fallback
	var clientKey string

	// Primary: Authentication-based (highest confidence)
	if fp.Authorization != "" {
		clientKey = "auth:" + fp.FingerprintHash
	} else if fp.SessionCookie != "" {
		clientKey = "session:" + fp.FingerprintHash
	} else if len(fp.SessionTokens) > 0 {
		clientKey = "token:" + fp.FingerprintHash
	} else if fp.Confidence >= 0.3 {
		// Medium confidence: comprehensive fingerprint
		clientKey = "fingerprint:" + fp.FingerprintHash
	} else {
		// Low confidence: basic IP + user agent
		basic := fp.ClientIP + ":" + hashSensitive(fp.UserAgent)
		clientKey = "basic:" + hashSensitive(basic)
	}

	// Store fingerprint for this client key
	clientTracker.mu.Lock()
	if session, exists := clientTracker.clientSessions[clientKey]; exists {
		session.Fingerprint = fp
		session.LastSeen = time.Now()
	} else {
		clientTracker.clientSessions[clientKey] = &ClientSession{
			ID:             clientKey,
			Fingerprint:    fp,
			LastSeen:       time.Now(),
			TunnelMappings: make(map[string]int),
			SuccessRate:    make(map[string]float64),
			Confidence:     fp.Confidence,
		}
	}
	clientTracker.mu.Unlock()

	return clientKey
}

// ClientTracker methods for managing tunnel mappings

// GetBestTunnel returns the most likely tunnel for a client
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
		"high (>0.7)":      0,
		"medium (0.3-0.7)": 0,
		"low (<0.3)":       0,
	}

	for _, session := range ct.clientSessions {
		conf := session.Confidence
		if conf > 0.7 {
			confidenceRanges["high (>0.7)"]++
		} else if conf >= 0.3 {
			confidenceRanges["medium (0.3-0.7)"]++
		} else {
			confidenceRanges["low (<0.3)"]++
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

	// Look for /pub/{tunnelID}/ pattern
	re := regexp.MustCompile(`^/pub/([a-f0-9\-]+)(/.*)?$`)
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

// smartFallbackHandler handles requests that don't match existing routes
func smartFallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Skip if this is already a /pub/ request (avoid infinite loops)
	if strings.HasPrefix(r.URL.Path, "/pub/") ||
		strings.HasPrefix(r.URL.Path, "/register") ||
		strings.HasPrefix(r.URL.Path, "/ws") ||
		strings.HasPrefix(r.URL.Path, "/tcp/") ||
		strings.HasPrefix(r.URL.Path, "/health") {
		http.NotFound(w, r)
		return
	}

	// Generate client key for enhanced tracking
	clientKey := generateClientKey(r)
	isAsset := isAssetRequest(r.URL.Path)
	isAPI := isAPIRequest(r.URL.Path)

	log.Printf("Smart routing: handling request %s (asset: %v, api: %v, client: %s)", r.URL.Path, isAsset, isAPI, clientKey)

	// PRIORITY: Single tunnel optimization for ALL requests when only one tunnel exists
	tunnelIDs := getActiveTunnelIDs()
	log.Printf("Smart routing: active tunnels count: %d", len(tunnelIDs))

	// If only one tunnel exists, route ALL requests to it (much simpler and more reliable)
	if len(tunnelIDs) == 1 {
		tunnelID := tunnelIDs[0]
		requestType := "regular"
		if isAPI {
			requestType = "api"
		} else if isAsset {
			requestType = "asset"
		}

		log.Printf("Smart routing: SINGLE TUNNEL - routing %s request %s to tunnel %s", requestType, r.URL.Path, tunnelID)

		// Add extra logging for API requests to help debug 404 issues
		if isAPI {
			log.Printf("Smart routing: API REQUEST DETAILS - Method: %s, Path: %s, Headers: %v", r.Method, r.URL.Path, r.Header)
		}

		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			// Learn this mapping for future requests
			clientTracker.LearnMapping(clientKey, tunnelID)
			clientTracker.RecordSuccess(clientKey, tunnelID)

			// Cache assets and record mappings
			if isAsset {
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = tunnelID
				assetCacheMu.Unlock()
				recordClientAssetMapping(clientKey, tunnelID)
			} else if !isAPI {
				// Record asset mapping for regular pages
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (single-tunnel-%s-SUCCESS)", r.URL.Path, tunnelID, requestType)
			return
		} else {
			log.Printf("Smart routing: SINGLE TUNNEL routing failed for %s %s -> %s", requestType, r.URL.Path, tunnelID)
			// Don't return here - try other strategies below
		}
	} else {
		log.Printf("Smart routing: multiple tunnels detected (%d), using advanced routing", len(tunnelIDs))
	}

	// Check asset cache first
	assetCacheMu.RLock()
	if cachedTunnelID, exists := assetCache[r.URL.Path]; exists {
		assetCacheMu.RUnlock()
		if tryTunnelRouteWithTimeout(w, r, cachedTunnelID, isAsset) {
			// Record success in client tracker
			clientTracker.RecordSuccess(clientKey, cachedTunnelID)
			log.Printf("Smart routing: %s -> tunnel %s (cached)", r.URL.Path, cachedTunnelID)
			return
		}
		// Remove invalid cache entry
		assetCacheMu.Lock()
		delete(assetCache, r.URL.Path)
		assetCacheMu.Unlock()
	} else {
		assetCacheMu.RUnlock()
	}

	// Enhanced Strategy: Check client asset mapping for asset requests
	if isAsset {
		if mappedTunnelID := getClientAssetMappingWithFallback(r, clientKey); mappedTunnelID != "" {
			if tryTunnelRouteWithTimeout(w, r, mappedTunnelID, isAsset) {
				// Cache successful mapping
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = mappedTunnelID
				assetCacheMu.Unlock()

				clientTracker.RecordSuccess(clientKey, mappedTunnelID)
				log.Printf("Smart routing: %s -> tunnel %s (client-asset-mapping)", r.URL.Path, mappedTunnelID)
				return
			} else {
				log.Printf("Smart routing: client asset mapping failed for %s -> %s", r.URL.Path, mappedTunnelID)
			}
		}

		// If we reached here and only have one tunnel, something went wrong above
		// Let's try one more time with explicit handling
		tunnelIDs := getActiveTunnelIDs()
		if len(tunnelIDs) == 1 {
			tunnelID := tunnelIDs[0]
			log.Printf("Smart routing: RETRY - asset %s with single tunnel %s", r.URL.Path, tunnelID)
			if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
				// Cache successful mapping
				assetCacheMu.Lock()
				assetCache[r.URL.Path] = tunnelID
				assetCacheMu.Unlock()

				// Record asset mapping for this client
				recordClientAssetMapping(clientKey, tunnelID)
				clientTracker.RecordSuccess(clientKey, tunnelID)

				log.Printf("Smart routing: %s -> tunnel %s (asset-retry-SUCCESS)", r.URL.Path, tunnelID)
				return
			} else {
				log.Printf("Smart routing: RETRY failed for asset %s -> %s", r.URL.Path, tunnelID)
			}
		}
	}

	// Strategy 1: Enhanced Client Tracking (EXISTING)
	if tunnelID := clientTracker.GetBestTunnel(clientKey); tunnelID != "" {
		confidence := clientTracker.GetConfidence(clientKey, tunnelID)
		// Lower confidence threshold for API endpoints since they're critical
		minConfidence := 0.7
		if isAPIRequest(r.URL.Path) {
			minConfidence = 0.3 // Lower threshold for API calls
		}

		if confidence > minConfidence && tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)

			// Record geographical routing success (NEW)
			clientIP := extractRealClientIP(r)
			recordIPTunnelMapping(clientIP, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (client-tracker, conf=%.2f)", r.URL.Path, tunnelID, confidence)
			return
		} else if confidence > minConfidence {
			// High confidence but failed - record failure
			clientTracker.RecordFailure(clientKey, tunnelID)
		}
	}

	// Strategy 1.5: IP-based Geographical Routing (NEW)
	clientIP := extractRealClientIP(r)
	if tunnelID := getIPTunnelMapping(clientIP); tunnelID != "" {
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)
			recordIPTunnelMapping(clientIP, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (ip-mapping, ip=%s)", r.URL.Path, tunnelID, clientIP)
			return
		} else {
			log.Printf("Smart routing: IP mapping failed for %s -> %s (ip=%s)", r.URL.Path, tunnelID, clientIP)
		}
	}

	// Strategy 1.6: Geographical Region Routing (NEW)
	if tunnelID := getGeoTunnelPreference(clientIP); tunnelID != "" {
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, tunnelID)
			recordIPTunnelMapping(clientIP, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			geoData := lookupIPGeoData(clientIP)
			geoKey := ""
			if geoData != nil {
				geoKey = geoData.Country + "_" + geoData.Region
			}
			log.Printf("Smart routing: %s -> tunnel %s (geo-preference, ip=%s, geo=%s)", r.URL.Path, tunnelID, clientIP, geoKey)
			return
		} else {
			geoData := lookupIPGeoData(clientIP)
			geoKey := ""
			if geoData != nil {
				geoKey = geoData.Country + "_" + geoData.Region
			}
			log.Printf("Smart routing: Geo preference failed for %s -> %s (ip=%s, geo=%s)", r.URL.Path, tunnelID, clientIP, geoKey)
		}
	}

	// Strategy 2: Try Referer-based routing (Enhanced)
	if tunnelID := extractTunnelFromReferer(r); tunnelID != "" {
		if tryTunnelRouteWithTimeout(w, r, tunnelID, isAsset) {
			// Learn this mapping for future requests
			clientTracker.LearnMapping(clientKey, tunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, tunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (referer)", r.URL.Path, tunnelID)
			return
		}
	}

	// Strategy 3: Try all active tunnels in parallel (enhanced with learning)
	if len(tunnelIDs) == 0 {
		http.NotFound(w, r)
		return
	}

	// Read request body once for reuse
	bodyBytes, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// Use channels to handle parallel attempts
	type tunnelResult struct {
		tunnelID string
		success  bool
	}

	resultCh := make(chan tunnelResult, len(tunnelIDs))

	// Try each tunnel in parallel with appropriate timeout
	for _, tunnelID := range tunnelIDs {
		go func(tid string) {
			// Create a new request with the same body for each attempt
			newReq := r.Clone(r.Context())
			newReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

			success := tryTunnelRouteWithTimeout(&discardResponseWriter{}, newReq, tid, isAsset)
			resultCh <- tunnelResult{tunnelID: tid, success: success}
		}(tunnelID)
	}

	// Collect all results to learn from failures too
	var successfulTunnelID string
	var results []tunnelResult

	for range len(tunnelIDs) {
		result := <-resultCh
		results = append(results, result)
		if result.success && successfulTunnelID == "" {
			successfulTunnelID = result.tunnelID
		}
	}

	// Learn from all results
	for _, result := range results {
		if result.success {
			clientTracker.LearnMapping(clientKey, result.tunnelID)
			// Record geographical mapping for successful results (NEW)
			recordIPTunnelMapping(clientIP, result.tunnelID)
		} else {
			clientTracker.RecordFailure(clientKey, result.tunnelID)
		}
	}

	// If we found a working tunnel, make the real request
	if successfulTunnelID != "" {
		// Create final request with original body
		finalReq := r.Clone(r.Context())
		finalReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		if tryTunnelRouteWithTimeout(w, finalReq, successfulTunnelID, isAsset) {
			clientTracker.RecordSuccess(clientKey, successfulTunnelID)

			// Record geographical mapping (NEW)
			recordIPTunnelMapping(clientIP, successfulTunnelID)

			// Record asset mapping for non-asset requests (main pages)
			if !isAsset {
				recordClientAssetMapping(clientKey, successfulTunnelID)
			}

			log.Printf("Smart routing: %s -> tunnel %s (parallel)", r.URL.Path, successfulTunnelID)
			return
		}
	}

	// ULTIMATE FALLBACK: Single tunnel catch-all for any missed requests
	if len(tunnelIDs) == 1 {
		tunnelID := tunnelIDs[0]
		log.Printf("Smart routing: ULTIMATE FALLBACK - trying single tunnel %s for %s", tunnelID, r.URL.Path)

		// Create final request with original body
		finalReq := r.Clone(r.Context())
		finalReq.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		// Use extended timeout for ultimate fallback to give agent more time
		extendedTimeout := 30 * time.Second
		if isAsset {
			extendedTimeout = 45 * time.Second
		}

		ctx, cancel := context.WithTimeout(r.Context(), extendedTimeout)
		defer cancel()

		// Try with extended timeout for final attempt
		ac := getAgent(tunnelID)
		if ac != nil {
			reqID := uuid.NewString()
			req := &ReqFrame{
				Type:    "req",
				ReqID:   reqID,
				Method:  finalReq.Method,
				Path:    finalReq.URL.Path,
				Query:   finalReq.URL.RawQuery,
				Headers: finalReq.Header,
				Body:    bodyBytes,
			}

			respCh := make(chan *RespFrame, 1)
			ac.registerWaiter(reqID, respCh)

			if err := ac.writeEncrypted(ctx, req); err == nil {
				select {
				case resp := <-respCh:
					clientTracker.RecordSuccess(clientKey, tunnelID)

					// Record geographical mapping (NEW)
					recordIPTunnelMapping(clientIP, tunnelID)

					// Cache assets and record mappings
					if isAsset {
						assetCacheMu.Lock()
						assetCache[r.URL.Path] = tunnelID
						assetCacheMu.Unlock()
						recordClientAssetMapping(clientKey, tunnelID)
					} else if !isAPI {
						recordClientAssetMapping(clientKey, tunnelID)
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

					log.Printf("Smart routing: %s -> tunnel %s (ultimate-fallback-EXTENDED-SUCCESS)", r.URL.Path, tunnelID)
					return
				case <-ctx.Done():
					log.Printf("Smart routing: ultimate fallback timeout for %s -> %s", r.URL.Path, tunnelID)
				}
			} else {
				log.Printf("Smart routing: ultimate fallback write error for %s -> %s: %v", r.URL.Path, tunnelID, err)
			}
		} else {
			log.Printf("Smart routing: ultimate fallback - agent %s not found", tunnelID)
		}
	}

	// No tunnel worked
	log.Printf("Smart routing failed: %s (tried %d tunnels, isAPI: %v, isAsset: %v)", r.URL.Path, len(tunnelIDs), isAPI, isAsset)
	http.NotFound(w, r)
}

// discardResponseWriter is used for testing tunnel responses without writing to the real response
type discardResponseWriter struct {
	headers http.Header
	status  int
}

func (d *discardResponseWriter) Header() http.Header {
	if d.headers == nil {
		d.headers = make(http.Header)
	}
	return d.headers
}

func (d *discardResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (d *discardResponseWriter) WriteHeader(status int) {
	d.status = status
}

func main() {
	// Start client tracker cleanup routine
	go func() {
		ticker := time.NewTicker(clientTracker.cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			clientTracker.CleanupExpiredSessions()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/ws", wsHandler) // agent websocket
	mux.HandleFunc("/pub/", publicHandler)
	mux.HandleFunc("/tcp/", tcpHandler)
	mux.HandleFunc("/health", healthHandler)
	// Smart fallback handler - must be last (catch-all)
	mux.HandleFunc("/", smartFallbackHandler)

	// Cloud Run: No tunnel persistence needed - agents will reconnect and provide tunnel info
	log.Println("Starting stateless server for Cloud Run - agents will re-register tunnel info on reconnection")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  0, // allow long-lived websockets
		WriteTimeout: 0,
		IdleTimeout:  0,
	}
	log.Printf("listening on :%s with encrypted tunnels", port)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

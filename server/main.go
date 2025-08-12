package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
}

// TcpConn represents an active TCP connection through the tunnel
type TcpConn struct {
	id       string
	dataCh   chan []byte
	closeCh  chan string
	closed   bool
	closeMu  sync.Mutex
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
	Secret   string
	Protocol string // "http" or "tcp"
	Port     int    // for TCP tunnels
}

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
	}

	tunnelsMu.Lock()
	tunnels[id] = tunnelInfo
	tunnelsMu.Unlock()

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

	// Set larger message size limit to match agent (10MB)
	c.SetReadLimit(10 * 1024 * 1024)

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
		id:          id,
		secret:      secret,
		ws:          c,
		cipher:      cipher,
		waiters:     make(map[string]chan *RespFrame),
		tcpConns:    make(map[string]*TcpConn),
		connectedAt: time.Now(),
	}

	agentsMu.Lock()
	agents[id] = ac
	agentsMu.Unlock()

	log.Printf("agent %s connected with encrypted tunnel", id)

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
		ActiveConnections []agentInfo `json:"active_connections"`
		ConnectionCount   int         `json:"connection_count"`
	}{
		ActiveConnections: make([]agentInfo, 0, len(agents)),
		ConnectionCount:   len(agents),
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
	tunnelsMu.RLock()
	defer tunnelsMu.RUnlock()
	info, ok := tunnels[id]
	return ok && info.Secret == secret
}

func getTunnelInfo(id string) *TunnelInfo {
	tunnelsMu.RLock()
	defer tunnelsMu.RUnlock()
	return tunnels[id]
}

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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/ws", wsHandler) // agent websocket
	mux.HandleFunc("/pub/", publicHandler)
	mux.HandleFunc("/tcp/", tcpHandler)
	mux.HandleFunc("/health", healthHandler)

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

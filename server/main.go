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

type RegisterResp struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`
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

type agentConn struct {
	id          string
	secret      string
	ws          *websocket.Conn
	cipher      *crypto.StreamCipher
	connectedAt time.Time

	writeMu sync.Mutex

	// reqID -> channel to deliver response
	respMu  sync.Mutex
	waiters map[string]chan *RespFrame
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

// ---- global in-memory stores (PoC only) ----

var (
	// tunnel id -> secret
	tunnels   = map[string]string{}
	tunnelsMu sync.RWMutex

	// tunnel id -> active agent connection
	agents   = map[string]*agentConn{}
	agentsMu sync.RWMutex
)

// ---- handlers ----

func registerHandler(w http.ResponseWriter, r *http.Request) {
	id := uuid.NewString()
	secret := randHex(32)

	tunnelsMu.Lock()
	tunnels[id] = secret
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

	resp := RegisterResp{
		ID:        id,
		Secret:    secret,
		PublicURL: fmt.Sprintf("%s/pub/%s", publicBase, id),
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
	s, ok := tunnels[id]
	return ok && s == secret
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

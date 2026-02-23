package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

// --- Types ---

// Frame types exchanged between server and agent over WebSocket.
//
// Unified protocol: all HTTP responses use response_start/response_data/response_end.
// The agent doesn't distinguish between SSE, streaming, or regular HTTP — it just proxies.
type Frame struct {
	Type string `json:"type"`

	// Registration
	ID        string `json:"id,omitempty"`
	Secret    string `json:"secret,omitempty"`
	PublicURL string `json:"public_url,omitempty"`

	// HTTP request (server → agent)
	ReqID   string            `json:"req_id,omitempty"`
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`

	// HTTP response (agent → server) — unified streaming protocol
	// response_start: Status + RespHeaders
	// response_data:  Data (base64-encoded body chunk)
	// response_end:   signals body complete
	Status      int               `json:"status,omitempty"`
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	Data        string            `json:"data,omitempty"`

	// WebSocket forwarding
	ConnID      string `json:"conn_id,omitempty"`
	MessageType int    `json:"message_type,omitempty"`
	Direction   string `json:"direction,omitempty"`
}

// Tunnel represents a connected agent.
type Tunnel struct {
	ID     string
	Secret string
	Conn   *websocket.Conn
	Mu     sync.Mutex

	// Pending HTTP requests waiting for agent response.
	Pending sync.Map // req_id → chan *Frame

	// Active WebSocket connections being forwarded.
	WSConns sync.Map // conn_id → chan *Frame
}

// --- Global state ---

// clientMapping tracks which tunnel a client last visited.
type clientMapping struct {
	tunnelID string
	lastSeen time.Time
}

var (
	tunnels       = sync.Map{} // id → *Tunnel
	clientTracker = sync.Map{} // client IP → *clientMapping
	serverURL     string
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	serverURL = os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:" + port
	}

	http.HandleFunc("/__ws__", handleAgentWS)
	http.HandleFunc("/__health__", handleHealth)
	http.HandleFunc("/", handlePublic)

	log.Printf("Tunnel server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// --- Agent WebSocket handler ---

func handleAgentWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("ws accept: %v", err)
		return
	}
	conn.SetReadLimit(8 * 1024 * 1024) // 8MB

	// Read registration frame
	ctx := r.Context()
	_, msg, err := conn.Read(ctx)
	if err != nil {
		log.Printf("ws read register: %v", err)
		conn.Close(websocket.StatusInternalError, "read failed")
		return
	}

	var reg Frame
	if err := json.Unmarshal(msg, &reg); err != nil || reg.Type != "register" {
		conn.Close(websocket.StatusInvalidFramePayloadData, "expected register")
		return
	}

	// Create or reconnect tunnel
	id := reg.ID
	secret := reg.Secret
	if id == "" {
		id = uuid.New().String()[:8]
		secret = uuid.New().String()[:16]
	}

	tunnel := &Tunnel{ID: id, Secret: secret, Conn: conn}

	// Check if reconnecting with valid credentials
	if existing, ok := tunnels.Load(id); ok {
		t := existing.(*Tunnel)
		if t.Secret != secret {
			conn.Close(websocket.StatusPolicyViolation, "bad secret")
			return
		}
		t.Mu.Lock()
		t.Conn = conn
		t.Mu.Unlock()
		tunnel = t
	} else {
		tunnels.Store(id, tunnel)
	}

	// Derive public URL from the request so it works on any deployment
	pubBase := serverURL
	if host := r.Host; host != "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		pubBase = scheme + "://" + host
	}
	pubURL := fmt.Sprintf("%s/__pub__/%s/", pubBase, id)
	resp := Frame{
		Type:      "register_response",
		ID:        id,
		Secret:    secret,
		PublicURL: pubURL,
	}
	data, _ := json.Marshal(resp)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		log.Printf("ws write register_response: %v", err)
		return
	}

	log.Printf("Agent registered: %s → %s", id, pubURL)

	// Start ping loop
	go pingLoop(tunnel)

	// Read loop: handle responses from agent
	for {
		_, msg, err := conn.Read(context.Background())
		if err != nil {
			log.Printf("Agent %s disconnected: %v", id, err)
			return
		}

		var frame Frame
		if err := json.Unmarshal(msg, &frame); err != nil {
			log.Printf("Agent %s bad frame: %v", id, err)
			continue
		}

		switch frame.Type {
		case "response_start", "response_data", "response_end":
			if ch, ok := tunnel.Pending.Load(frame.ReqID); ok {
				select {
				case ch.(chan *Frame) <- &frame:
				default:
					log.Printf("Agent %s: dropping frame for req %s (channel full)", id, frame.ReqID)
				}
			}
		case "ws_data":
			if ch, ok := tunnel.WSConns.Load(frame.ConnID); ok {
				ch.(chan *Frame) <- &frame
			}
		case "ws_close":
			if ch, ok := tunnel.WSConns.Load(frame.ConnID); ok {
				close(ch.(chan *Frame))
				tunnel.WSConns.Delete(frame.ConnID)
			}
		case "pong":
			// Agent is alive
		default:
			log.Printf("Agent %s unknown frame type: %s", id, frame.Type)
		}
	}
}

func pingLoop(t *Tunnel) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		t.Mu.Lock()
		conn := t.Conn
		t.Mu.Unlock()

		ping := Frame{Type: "ping"}
		data, _ := json.Marshal(ping)
		if err := conn.Write(context.Background(), websocket.MessageText, data); err != nil {
			return
		}
	}
}

// clientIP extracts the client IP from the request.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the chain is the original client
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i != -1 {
		return addr[:i]
	}
	return addr
}

// trackClient records client → tunnel mapping for SPA asset routing.
func trackClient(r *http.Request, tunnelID string) {
	ip := clientIP(r)
	clientTracker.Store(ip, &clientMapping{
		tunnelID: tunnelID,
		lastSeen: time.Now(),
	})
}

// --- Public HTTP handler ---

func handlePublic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	var tunnelID string
	var fwdPath string
	var tunnel *Tunnel

	if strings.HasPrefix(path, "/__pub__/") {
		// Extract tunnel ID from path: /__pub__/{id}/...
		rest := strings.TrimPrefix(path, "/__pub__/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) == 0 {
			http.NotFound(w, r)
			return
		}
		tunnelID = parts[0]
		fwdPath = "/"
		if len(parts) > 1 {
			fwdPath = "/" + parts[1]
		}
		val, ok := tunnels.Load(tunnelID)
		if !ok {
			http.Error(w, "tunnel not found", http.StatusBadGateway)
			return
		}
		tunnel = val.(*Tunnel)
		// Track this client so subsequent bare-path requests (SPA assets) route here
		trackClient(r, tunnelID)
	} else {
		// Not under /__pub__/ — try to route via client tracker.
		// This handles SPA assets requested at root (e.g., /assets/index.js).
		ip := clientIP(r)
		val, ok := clientTracker.Load(ip)
		if !ok {
			http.NotFound(w, r)
			return
		}
		cm := val.(*clientMapping)
		if time.Since(cm.lastSeen) >= 30*time.Minute {
			http.NotFound(w, r)
			return
		}
		tval, tok := tunnels.Load(cm.tunnelID)
		if !tok {
			http.NotFound(w, r)
			return
		}
		tunnelID = cm.tunnelID
		fwdPath = path
		tunnel = tval.(*Tunnel)
	}

	// Check if this is a WebSocket upgrade
	if isWebSocketUpgrade(r) {
		handleWSForward(w, r, tunnel, fwdPath)
		return
	}

	// All HTTP requests (regular, SSE, streaming) go through the same unified handler.
	// The agent streams response bytes back regardless of response type.
	handleHTTPRequest(w, r, tunnel, fwdPath)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// --- Unified HTTP proxying ---

func handleHTTPRequest(w http.ResponseWriter, r *http.Request, t *Tunnel, path string) {
	reqID := uuid.New().String()[:8]

	// Read request body (base64-encoded for safe JSON transport)
	var body string
	if r.Body != nil {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
		if len(b) > 0 {
			body = base64.StdEncoding.EncodeToString(b)
		}
	}

	// Build headers map
	headers := make(map[string]string)
	for k, v := range r.Header {
		if !hopHeaders[k] {
			headers[k] = v[0]
		}
	}

	frame := Frame{
		Type:    "request",
		ReqID:   reqID,
		Method:  r.Method,
		Path:    path,
		Query:   r.URL.RawQuery,
		Headers: headers,
		Body:    body,
	}

	ch := make(chan *Frame, 64)
	t.Pending.Store(reqID, ch)
	defer t.Pending.Delete(reqID)

	data, _ := json.Marshal(frame)
	t.Mu.Lock()
	err := t.Conn.Write(r.Context(), websocket.MessageText, data)
	t.Mu.Unlock()
	if err != nil {
		http.Error(w, "agent unreachable", http.StatusBadGateway)
		return
	}

	// Unified response relay: receive response_start, then stream response_data
	// chunks, then response_end. Works identically for regular HTTP, SSE, and
	// chunked responses — the agent just proxies bytes from the local service.
	flusher, _ := w.(http.Flusher)
	headersWritten := false
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case frame := <-ch:
			if frame == nil {
				return
			}
			switch frame.Type {
			case "response_start":
				for k, v := range frame.RespHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(frame.Status)
				headersWritten = true
				if flusher != nil {
					flusher.Flush()
				}
				timeout.Reset(60 * time.Second)

			case "response_data":
				if !headersWritten {
					w.WriteHeader(200)
					headersWritten = true
				}
				chunk, _ := base64.StdEncoding.DecodeString(frame.Data)
				w.Write(chunk)
				if flusher != nil {
					flusher.Flush()
				}
				timeout.Reset(60 * time.Second)

			case "response_end":
				return
			}

		case <-timeout.C:
			if !headersWritten {
				http.Error(w, "timeout waiting for agent", http.StatusGatewayTimeout)
			}
			return

		case <-r.Context().Done():
			return
		}
	}
}

// --- WebSocket forwarding ---

func handleWSForward(w http.ResponseWriter, r *http.Request, t *Tunnel, path string) {
	connID := uuid.New().String()[:8]
	log.Printf("[WS:%s] New WebSocket forward request: path=%s query=%s tunnel=%s client=%s",
		connID, path, r.URL.RawQuery, t.ID, clientIP(r))

	// Accept the client's WebSocket
	clientConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("[WS:%s] Accept failed: %v", connID, err)
		return
	}
	defer func() {
		clientConn.Close(websocket.StatusNormalClosure, "")
		log.Printf("[WS:%s] Client connection closed", connID)
	}()
	clientConn.SetReadLimit(1 * 1024 * 1024)
	log.Printf("[WS:%s] Client WebSocket accepted", connID)

	// Register channel BEFORE sending ws_open to avoid race with agent response
	fromAgent := make(chan *Frame, 64)
	t.WSConns.Store(connID, fromAgent)
	defer func() {
		t.WSConns.Delete(connID)
		// Tell agent to close the backend WS
		closeFrame := Frame{Type: "ws_close", ConnID: connID}
		data, _ := json.Marshal(closeFrame)
		t.Mu.Lock()
		err := t.Conn.Write(context.Background(), websocket.MessageText, data)
		t.Mu.Unlock()
		if err != nil {
			log.Printf("[WS:%s] Failed to send ws_close to agent: %v", connID, err)
		} else {
			log.Printf("[WS:%s] Sent ws_close to agent", connID)
		}
	}()

	// Tell agent to open a WS connection to the local service
	openFrame := Frame{
		Type:   "ws_open",
		ConnID: connID,
		Path:   path,
		Query:  r.URL.RawQuery,
	}
	data, _ := json.Marshal(openFrame)
	t.Mu.Lock()
	err = t.Conn.Write(r.Context(), websocket.MessageText, data)
	t.Mu.Unlock()
	if err != nil {
		log.Printf("[WS:%s] Failed to send ws_open to agent: %v", connID, err)
		return
	}
	log.Printf("[WS:%s] Sent ws_open to agent (path=%s, query=%s)", connID, path, r.URL.RawQuery)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Client → Agent
	go func() {
		defer func() {
			log.Printf("[WS:%s] Client→Agent goroutine exiting", connID)
			cancel()
		}()
		for {
			msgType, msg, err := clientConn.Read(ctx)
			if err != nil {
				log.Printf("[WS:%s] Client read error: %v", connID, err)
				return
			}
			log.Printf("[WS:%s] Client→Agent: type=%d len=%d", connID, msgType, len(msg))
			fwd := Frame{
				Type:        "ws_data",
				ConnID:      connID,
				Data:        string(msg),
				MessageType: int(msgType),
				Direction:   "to_server",
			}
			data, _ := json.Marshal(fwd)
			t.Mu.Lock()
			err = t.Conn.Write(ctx, websocket.MessageText, data)
			t.Mu.Unlock()
			if err != nil {
				log.Printf("[WS:%s] Failed to forward client msg to agent: %v", connID, err)
				return
			}
		}
	}()

	// Agent → Client
	log.Printf("[WS:%s] Starting Agent→Client relay loop", connID)
	for {
		select {
		case frame, ok := <-fromAgent:
			if !ok {
				log.Printf("[WS:%s] fromAgent channel closed (agent sent ws_close)", connID)
				return
			}
			msgType := websocket.MessageText
			if frame.MessageType == int(websocket.MessageBinary) {
				msgType = websocket.MessageBinary
			}
			log.Printf("[WS:%s] Agent→Client: type=%d len=%d", connID, msgType, len(frame.Data))
			if err := clientConn.Write(ctx, msgType, []byte(frame.Data)); err != nil {
				log.Printf("[WS:%s] Failed to write to client: %v", connID, err)
				return
			}
		case <-ctx.Done():
			log.Printf("[WS:%s] Context cancelled: %v", connID, ctx.Err())
			return
		}
	}
}

// --- Health ---

func handleHealth(w http.ResponseWriter, r *http.Request) {
	count := 0
	tunnels.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","tunnels":%d}`, count)
}

// Hop-by-hop headers that should not be forwarded.
var hopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

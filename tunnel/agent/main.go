package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

// Frame matches the server's JSON protocol.
type Frame struct {
	Type string `json:"type"`

	// Registration
	ID        string `json:"id,omitempty"`
	Secret    string `json:"secret,omitempty"`
	PublicURL string `json:"public_url,omitempty"`

	// HTTP request
	ReqID   string            `json:"req_id,omitempty"`
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`

	// HTTP response
	Status      int               `json:"status,omitempty"`
	RespHeaders map[string]string `json:"resp_headers,omitempty"`
	RespBody    string            `json:"resp_body,omitempty"`

	// Streaming
	Data string `json:"data,omitempty"`
	Done bool   `json:"done,omitempty"`

	// WebSocket forwarding
	ConnID      string `json:"conn_id,omitempty"`
	MessageType int    `json:"message_type,omitempty"`
	Direction   string `json:"direction,omitempty"`
}

var (
	serverAddr string
	localAddr  string
	tunnelID   string
	secret     string
	httpClient = &http.Client{Timeout: 30 * time.Second}
)

func main() {
	flag.StringVar(&serverAddr, "server", "http://localhost:8080", "Tunnel server URL")
	flag.StringVar(&localAddr, "local", "http://localhost:3000", "Local service URL")
	flag.StringVar(&tunnelID, "id", "", "Tunnel ID (for reconnection)")
	flag.StringVar(&secret, "secret", "", "Tunnel secret (for reconnection)")
	flag.Parse()

	if !strings.HasPrefix(localAddr, "http") {
		localAddr = "http://" + localAddr
	}
	localAddr = strings.TrimRight(localAddr, "/")

	log.Printf("Connecting to %s, forwarding to %s", serverAddr, localAddr)

	backoff := time.Second
	for {
		err := run()
		log.Printf("Disconnected: %v. Reconnecting in %v...", err, backoff)
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		}
	}
}

func run() error {
	// Build WebSocket URL
	wsURL := strings.Replace(serverAddr, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/__ws__"

	ctx := context.Background()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(8 * 1024 * 1024)

	// Register
	reg := Frame{Type: "register", ID: tunnelID, Secret: secret}
	data, _ := json.Marshal(reg)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("write register: %w", err)
	}

	// Read registration response
	_, msg, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("read register_response: %w", err)
	}
	var resp Frame
	if err := json.Unmarshal(msg, &resp); err != nil {
		return fmt.Errorf("parse register_response: %w", err)
	}
	if resp.Type != "register_response" {
		return fmt.Errorf("unexpected frame: %s", resp.Type)
	}

	tunnelID = resp.ID
	secret = resp.Secret
	log.Printf("Registered! Public URL: %s", resp.PublicURL)

	// Active WS connections to local service
	wsConns := make(map[string]*websocket.Conn)

	// Message loop
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var frame Frame
		if err := json.Unmarshal(msg, &frame); err != nil {
			log.Printf("bad frame: %v", err)
			continue
		}

		switch frame.Type {
		case "request":
			go handleHTTPRequest(ctx, conn, frame)
		case "ws_open":
			go handleWSOpen(ctx, conn, frame, wsConns)
		case "ws_data":
			if ws, ok := wsConns[frame.ConnID]; ok {
				msgType := websocket.MessageText
				if frame.MessageType == int(websocket.MessageBinary) {
					msgType = websocket.MessageBinary
				}
				ws.Write(ctx, msgType, []byte(frame.Data))
			}
		case "ws_close":
			if ws, ok := wsConns[frame.ConnID]; ok {
				ws.Close(websocket.StatusNormalClosure, "")
				delete(wsConns, frame.ConnID)
			}
		case "ping":
			pong := Frame{Type: "pong"}
			data, _ := json.Marshal(pong)
			conn.Write(ctx, websocket.MessageText, data)
		default:
			log.Printf("unknown frame type: %s", frame.Type)
		}
	}
}

func handleHTTPRequest(ctx context.Context, conn *websocket.Conn, req Frame) {
	url := localAddr + req.Path
	if req.Query != "" {
		url += "?" + req.Query
	}

	var body io.Reader
	if req.Body != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			body = strings.NewReader(req.Body)
		} else {
			body = bytes.NewReader(decoded)
		}
	}

	httpReq, err := http.NewRequest(req.Method, url, body)
	if err != nil {
		sendError(ctx, conn, req.ReqID, 502, "bad request: "+err.Error())
		return
	}

	for k, v := range req.Headers {
		if strings.EqualFold(k, "Content-Length") {
			continue // body length may differ after base64 decode
		}
		httpReq.Header.Set(k, v)
	}

	// Check if this should be streamed (SSE)
	isSSE := strings.Contains(req.Headers["Accept"], "text/event-stream") ||
		strings.Contains(req.Path, "/stream") ||
		strings.Contains(req.Path, "/events")

	if isSSE {
		handleStreamingHTTP(ctx, conn, req.ReqID, httpReq)
		return
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		sendError(ctx, conn, req.ReqID, 502, "local service error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = v[0]
	}

	frame := Frame{
		Type:        "response",
		ReqID:       req.ReqID,
		Status:      resp.StatusCode,
		RespHeaders: headers,
		RespBody:    base64.StdEncoding.EncodeToString(respBody),
	}
	data, _ := json.Marshal(frame)
	conn.Write(ctx, websocket.MessageText, data)
}

func handleStreamingHTTP(ctx context.Context, conn *websocket.Conn, reqID string, httpReq *http.Request) {
	client := &http.Client{} // no timeout for streaming
	resp, err := client.Do(httpReq)
	if err != nil {
		sendError(ctx, conn, reqID, 502, "local service error: "+err.Error())
		return
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = v[0]
	}

	// Send streaming start
	start := Frame{
		Type:        "streaming_start",
		ReqID:       reqID,
		Status:      resp.StatusCode,
		RespHeaders: headers,
	}
	data, _ := json.Marshal(start)
	conn.Write(ctx, websocket.MessageText, data)

	// Stream chunks
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := Frame{
				Type:  "streaming_chunk",
				ReqID: reqID,
				Data:  string(buf[:n]),
			}
			data, _ := json.Marshal(chunk)
			conn.Write(ctx, websocket.MessageText, data)
		}
		if err != nil {
			break
		}
	}

	// Send streaming end
	end := Frame{Type: "streaming_end", ReqID: reqID}
	data, _ = json.Marshal(end)
	conn.Write(ctx, websocket.MessageText, data)
}

func handleWSOpen(ctx context.Context, agentConn *websocket.Conn, frame Frame, wsConns map[string]*websocket.Conn) {
	// Build local WS URL
	wsURL := strings.Replace(localAddr, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += frame.Path
	if frame.Query != "" {
		wsURL += "?" + frame.Query
	}

	localConn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		log.Printf("ws_open to %s failed: %v", wsURL, err)
		closeFrame := Frame{Type: "ws_close", ConnID: frame.ConnID}
		data, _ := json.Marshal(closeFrame)
		agentConn.Write(ctx, websocket.MessageText, data)
		return
	}
	localConn.SetReadLimit(1 * 1024 * 1024)
	wsConns[frame.ConnID] = localConn

	// Read from local WS → send to server
	go func() {
		defer func() {
			localConn.Close(websocket.StatusNormalClosure, "")
			delete(wsConns, frame.ConnID)
			closeFrame := Frame{Type: "ws_close", ConnID: frame.ConnID}
			data, _ := json.Marshal(closeFrame)
			agentConn.Write(ctx, websocket.MessageText, data)
		}()
		for {
			msgType, msg, err := localConn.Read(ctx)
			if err != nil {
				return
			}
			fwd := Frame{
				Type:        "ws_data",
				ConnID:      frame.ConnID,
				Data:        string(msg),
				MessageType: int(msgType),
				Direction:   "to_client",
			}
			data, _ := json.Marshal(fwd)
			agentConn.Write(ctx, websocket.MessageText, data)
		}
	}()
}

func sendError(ctx context.Context, conn *websocket.Conn, reqID string, status int, msg string) {
	frame := Frame{
		Type:        "response",
		ReqID:       reqID,
		Status:      status,
		RespHeaders: map[string]string{"Content-Type": "text/plain"},
		RespBody:    base64.StdEncoding.EncodeToString([]byte(msg)),
	}
	data, _ := json.Marshal(frame)
	conn.Write(ctx, websocket.MessageText, data)
}


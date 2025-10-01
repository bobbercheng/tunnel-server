package agentlib

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// WebSocket connection tracking
var (
	webSocketConnectionsNew = make(map[string]*websocket.Conn)
	webSocketMutexNew       sync.RWMutex
)

// isWebSocketUpgradeNew checks if the request is a WebSocket upgrade request
func (a *Agent) isWebSocketUpgradeNew(req *ReqFrame) bool {
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

// handleWebSocketUpgradeNew handles WebSocket upgrade and establishes bidirectional forwarding
func (a *Agent) handleWebSocketUpgradeNew(ctx context.Context, req *ReqFrame, writeEncrypted func(v any) error) {
	// Step 1: Establish WebSocket connection to local service
	localConn, err := a.establishLocalWebSocketNew(req)
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
	a.forwardWebSocketFramesNew(ctx, req.ReqID, localConn, writeEncrypted)
}

// establishLocalWebSocketNew establishes WebSocket connection to local service
func (a *Agent) establishLocalWebSocketNew(req *ReqFrame) (*websocket.Conn, error) {
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
	webSocketMutexNew.Lock()
	webSocketConnectionsNew[req.ReqID] = conn
	webSocketMutexNew.Unlock()

	return conn, nil
}

// forwardWebSocketFramesNew handles bidirectional WebSocket frame forwarding
func (a *Agent) forwardWebSocketFramesNew(ctx context.Context, reqID string, localConn *websocket.Conn, writeEncrypted func(v any) error) {
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

// handleWebSocketFrameNew forwards frames from server to local WebSocket
func (a *Agent) handleWebSocketFrameNew(frame *WebSocketFrame) {
	webSocketMutexNew.RLock()
	conn, exists := webSocketConnectionsNew[frame.ReqID]
	webSocketMutexNew.RUnlock()

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
		webSocketMutexNew.Lock()
		delete(webSocketConnectionsNew, frame.ReqID)
		webSocketMutexNew.Unlock()
		conn.Close(websocket.StatusInternalError, "Write failed")
		return
	}

	log.Printf("AGENT WEBSOCKET: Forwarded frame from server to local | ReqID: %s | Type: %d | Size: %d bytes",
		frame.ReqID, frame.MessageType, len(frame.Data))
}

// handleWebSocketCloseNew handles WebSocket close from server
func (a *Agent) handleWebSocketCloseNew(frame *WebSocketFrame) {
	webSocketMutexNew.Lock()
	conn, exists := webSocketConnectionsNew[frame.ReqID]
	if exists {
		delete(webSocketConnectionsNew, frame.ReqID)
	}
	webSocketMutexNew.Unlock()

	if exists {
		log.Printf("AGENT WEBSOCKET: Closing local WebSocket connection | ReqID: %s", frame.ReqID)
		conn.Close(websocket.StatusNormalClosure, "Server closed connection")
	}
}
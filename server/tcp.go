package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"
)

// TCP tunneling functionality

// tcpHandler handles TCP tunnel connections
func tcpHandler(w http.ResponseWriter, r *http.Request) {
	// /__tcp__/{id}
	path := strings.TrimPrefix(r.URL.Path, "/__tcp__/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "missing tunnel id", http.StatusBadRequest)
		return
	}
	tunnelID := parts[0]

	ac := getAgent(tunnelID)
	if ac == nil {
		http.Error(w, "agent not connected", http.StatusBadGateway)
		return
	}

	// Get tunnel info to verify it's a TCP tunnel
	tunnelsMu.RLock()
	tunnel, exists := tunnels[tunnelID]
	tunnelsMu.RUnlock()

	if !exists {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	if tunnel.Protocol != "tcp" {
		http.Error(w, "not a TCP tunnel", http.StatusBadRequest)
		return
	}

	// Check if this is a WebSocket upgrade request
	isWebSocket := strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"

	if isWebSocket {
		// Handle WebSocket-based TCP tunnel (Cloud Run compatible)
		handleTcpWebSocket(w, r, ac, tunnel, tunnelID)
		return
	}

	// Fallback to HTTP hijacking for backward compatibility (doesn't work on Cloud Run)
	// Upgrade connection to raw TCP proxy
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		log.Printf("TCP hijack failed for tunnel %s: %v", tunnelID, err)
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Send success response before starting proxy
	response := "HTTP/1.1 200 Connection established\r\n\r\n"
	if _, err := bufrw.Write([]byte(response)); err != nil {
		log.Printf("TCP response write failed for tunnel %s: %v", tunnelID, err)
		return
	}
	if err := bufrw.Flush(); err != nil {
		log.Printf("TCP response flush failed for tunnel %s: %v", tunnelID, err)
		return
	}

	// Start TCP proxy through WebSocket tunnel
	connID := uuid.NewString()
	tcpConn := &TcpConn{
		id:      connID,
		dataCh:  make(chan []byte, 100),
		closeCh: make(chan string, 1),
		closed:  false,
	}

	// Register TCP connection
	ac.tcpConnsMu.Lock()
	ac.tcpConns[connID] = tcpConn
	ac.tcpConnsMu.Unlock()

	defer func() {
		ac.tcpConnsMu.Lock()
		delete(ac.tcpConns, connID)
		ac.tcpConnsMu.Unlock()
		tcpConn.close("server cleanup")
	}()

	// Send TCP connect frame to agent
	connectFrame := &TcpConnectFrame{
		Type:   "tcp_connect",
		ConnID: connID,
		Port:   tunnel.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ac.writeEncrypted(ctx, connectFrame); err != nil {
		log.Printf("Failed to send TCP connect to agent %s: %v", tunnelID, err)
		return
	}

	log.Printf("Started TCP proxy for tunnel %s, connection %s, port %d", tunnelID, connID, tunnel.Port)

	// Start bidirectional data relay
	go tcpRelayFromClient(conn, ac, connID)
	tcpRelayToClient(conn, tcpConn)

	log.Printf("TCP proxy ended for tunnel %s, connection %s", tunnelID, connID)
}

// handleTcpWebSocket handles WebSocket-based TCP tunnel (Cloud Run compatible)
func handleTcpWebSocket(w http.ResponseWriter, r *http.Request, ac *agentConn, tunnel *TunnelInfo, tunnelID string) {
	// Upgrade to WebSocket
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("WebSocket accept failed for TCP tunnel %s: %v", tunnelID, err)
		return
	}
	defer ws.Close(websocket.StatusInternalError, "server error")

	// Start TCP proxy through WebSocket tunnel to agent
	connID := uuid.NewString()
	tcpConn := &TcpConn{
		id:      connID,
		dataCh:  make(chan []byte, 100),
		closeCh: make(chan string, 1),
		closed:  false,
	}

	// Register TCP connection
	ac.tcpConnsMu.Lock()
	ac.tcpConns[connID] = tcpConn
	ac.tcpConnsMu.Unlock()

	defer func() {
		ac.tcpConnsMu.Lock()
		delete(ac.tcpConns, connID)
		ac.tcpConnsMu.Unlock()
		tcpConn.close("server cleanup")
	}()

	// Send TCP connect frame to agent
	connectFrame := &TcpConnectFrame{
		Type:   "tcp_connect",
		ConnID: connID,
		Port:   tunnel.Port,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ac.writeEncrypted(ctx, connectFrame); err != nil {
		log.Printf("Failed to send TCP connect to agent %s: %v", tunnelID, err)
		return
	}

	log.Printf("Started WebSocket TCP proxy for tunnel %s, connection %s, port %d", tunnelID, connID, tunnel.Port)

	// Start bidirectional data relay
	done := make(chan struct{}, 2)

	// Forward data from WebSocket client to agent
	go func() {
		defer func() {
			done <- struct{}{}
		}()

		for {
			msgType, data, err := ws.Read(ctx)
			if err != nil {
				if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
					log.Printf("WebSocket read error for connection %s: %v", connID, err)
				}
				break
			}

			if msgType != websocket.MessageBinary {
				log.Printf("Unexpected WebSocket message type for connection %s: %v", connID, msgType)
				continue
			}

			if len(data) == 0 {
				continue
			}

			// Send data to agent
			dataFrame := &TcpDataFrame{
				Type:   "tcp_data",
				ConnID: connID,
				Data:   data,
			}

			if err := ac.writeEncrypted(ctx, dataFrame); err != nil {
				log.Printf("Failed to send TCP data to agent %s: %v", ac.id, err)
				break
			}
		}

		// Send disconnect frame when client connection closes
		disconnectFrame := &TcpDisconnectFrame{
			Type:   "tcp_disconnect",
			ConnID: connID,
			Reason: "client disconnected",
		}

		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer disconnectCancel()

		if err := ac.writeEncrypted(disconnectCtx, disconnectFrame); err != nil {
			log.Printf("Failed to send TCP disconnect to agent %s: %v", ac.id, err)
		}
	}()

	// Forward data from agent to WebSocket client
	go func() {
		defer func() {
			done <- struct{}{}
		}()

		for {
			select {
			case data, ok := <-tcpConn.dataCh:
				if !ok {
					return
				}

				if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
					log.Printf("WebSocket write error for connection %s: %v", connID, err)
					return
				}

			case reason := <-tcpConn.closeCh:
				log.Printf("TCP connection %s closed by agent: %s", connID, reason)
				return
			}
		}
	}()

	// Wait for either direction to close
	<-done
	ws.Close(websocket.StatusNormalClosure, "connection closed")
	log.Printf("WebSocket TCP proxy ended for tunnel %s, connection %s", tunnelID, connID)
}

// tcpRelayFromClient reads data from the client connection and sends it to the agent
func tcpRelayFromClient(clientConn net.Conn, ac *agentConn, connID string) {
	defer func() {
		// Send disconnect frame when client connection closes
		disconnectFrame := &TcpDisconnectFrame{
			Type:   "tcp_disconnect",
			ConnID: connID,
			Reason: "client disconnected",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := ac.writeEncrypted(ctx, disconnectFrame); err != nil {
			log.Printf("Failed to send TCP disconnect to agent %s: %v", ac.id, err)
		}
	}()

	buffer := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := clientConn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("TCP client read error for connection %s: %v", connID, err)
			}
			break
		}

		if n == 0 {
			continue
		}

		// Send data to agent
		dataFrame := &TcpDataFrame{
			Type:   "tcp_data",
			ConnID: connID,
			Data:   buffer[:n],
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := ac.writeEncrypted(ctx, dataFrame); err != nil {
			cancel()
			log.Printf("Failed to send TCP data to agent %s: %v", ac.id, err)
			break
		}
		cancel()
	}
}

// tcpRelayToClient reads data from the agent and sends it to the client connection
func tcpRelayToClient(clientConn net.Conn, tcpConn *TcpConn) {
	for {
		select {
		case data, ok := <-tcpConn.dataCh:
			if !ok {
				return
			}

			if _, err := clientConn.Write(data); err != nil {
				log.Printf("TCP client write error for connection %s: %v", tcpConn.id, err)
				return
			}

		case reason := <-tcpConn.closeCh:
			log.Printf("TCP connection %s closed by agent: %s", tcpConn.id, reason)
			return
		}
	}
}

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
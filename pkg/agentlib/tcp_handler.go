package agentlib

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

// handleTcpConnect establishes a new TCP connection to the local service
func (a *Agent) handleTcpConnect(ctx context.Context, frame *TcpConnectFrame, writeEncrypted func(v any) error) {
	// Connect to local TCP service
	var target string

	if strings.Contains(a.LocalURL, "://") {
		// Parse URL format (e.g., tcp://hostname:port or http://hostname)
		u, err := url.Parse(a.LocalURL)
		if err != nil {
			log.Printf("TCP: Failed to parse LocalURL '%s': %v", a.LocalURL, err)
			// Fallback to localhost
			target = fmt.Sprintf("localhost:%d", frame.Port)
		} else {
			target = fmt.Sprintf("%s:%d", u.Hostname(), frame.Port)
		}
	} else {
		// Bare hostname or IP address (e.g., internet.ford.com, 192.168.1.1, localhost)
		target = fmt.Sprintf("%s:%d", a.LocalURL, frame.Port)
	}

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("TCP: Failed to connect to local service | Target: %s | ConnID: %s | Error: %v",
			target, frame.ConnID, err)

		// Send disconnect frame back to server
		disconnectFrame := &TcpDisconnectFrame{
			Type:   "tcp_disconnect",
			ConnID: frame.ConnID,
			Reason: fmt.Sprintf("connection failed: %v", err),
		}
		writeEncrypted(disconnectFrame)
		return
	}

	log.Printf("TCP: Connected to local service | Target: %s | ConnID: %s", target, frame.ConnID)

	// Store connection
	a.tcpConnsMu.Lock()
	a.tcpConns[frame.ConnID] = conn
	a.tcpConnsMu.Unlock()

	// Process any buffered data that arrived before connection was established
	a.tcpPendingMu.Lock()
	bufferedFrames, hasPending := a.tcpPendingData[frame.ConnID]
	if hasPending {
		delete(a.tcpPendingData, frame.ConnID)
	}
	a.tcpPendingMu.Unlock()

	if hasPending && len(bufferedFrames) > 0 {
		log.Printf("TCP: Processing %d buffered data frames | ConnID: %s", len(bufferedFrames), frame.ConnID)
		for _, bufferedFrame := range bufferedFrames {
			// Forward buffered data to local connection
			_, err := conn.Write(bufferedFrame.Data)
			if err != nil {
				log.Printf("TCP: Error writing buffered data to local connection | ConnID: %s | Error: %v", frame.ConnID, err)
				// Continue processing other frames even if one fails
			} else {
				log.Printf("TCP: Forwarded buffered %d bytes to local connection | ConnID: %s", len(bufferedFrame.Data), frame.ConnID)
			}
		}
	}

	// Start reading from local connection and forwarding to server
	go func() {
		defer func() {
			// Clean up connection
			a.tcpConnsMu.Lock()
			delete(a.tcpConns, frame.ConnID)
			a.tcpConnsMu.Unlock()
			conn.Close()

			// Send disconnect notification
			disconnectFrame := &TcpDisconnectFrame{
				Type:   "tcp_disconnect",
				ConnID: frame.ConnID,
				Reason: "local connection closed",
			}
			writeEncrypted(disconnectFrame)
			log.Printf("TCP: Local connection closed | ConnID: %s", frame.ConnID)
		}()

		buffer := make([]byte, 32*1024) // 32KB buffer
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Set read timeout
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				log.Printf("TCP: Error reading from local connection | ConnID: %s | Error: %v", frame.ConnID, err)
				return
			}

			if n > 0 {
				// Forward data to server
				dataFrame := &TcpDataFrame{
					Type:   "tcp_data",
					ConnID: frame.ConnID,
					Data:   make([]byte, n),
				}
				copy(dataFrame.Data, buffer[:n])

				if err := writeEncrypted(dataFrame); err != nil {
					log.Printf("TCP: Failed to send data to server | ConnID: %s | Error: %v", frame.ConnID, err)
					return
				}
			}
		}
	}()
}

// handleTcpData forwards data from server to local TCP connection
func (a *Agent) handleTcpData(frame *TcpDataFrame) {
	a.tcpConnsMu.Lock()
	conn, exists := a.tcpConns[frame.ConnID]
	a.tcpConnsMu.Unlock()

	if !exists {
		// Connection doesn't exist yet - buffer the data until tcp_connect arrives
		log.Printf("TCP: Received data for connection not yet established, buffering | ConnID: %s | Size: %d bytes", frame.ConnID, len(frame.Data))

		a.tcpPendingMu.Lock()
		a.tcpPendingData[frame.ConnID] = append(a.tcpPendingData[frame.ConnID], frame)
		bufferSize := len(a.tcpPendingData[frame.ConnID])
		a.tcpPendingMu.Unlock()

		log.Printf("TCP: Buffered data frame | ConnID: %s | BufferSize: %d frames", frame.ConnID, bufferSize)
		return
	}

	// Forward data to local connection
	_, err := conn.Write(frame.Data)
	if err != nil {
		log.Printf("TCP: Error writing to local connection | ConnID: %s | Error: %v", frame.ConnID, err)
		// Connection is probably broken, clean up
		a.tcpConnsMu.Lock()
		delete(a.tcpConns, frame.ConnID)
		a.tcpConnsMu.Unlock()
		conn.Close()
		return
	}

	log.Printf("TCP: Forwarded %d bytes to local connection | ConnID: %s", len(frame.Data), frame.ConnID)
}

// handleTcpDisconnect closes the local TCP connection
func (a *Agent) handleTcpDisconnect(frame *TcpDisconnectFrame) {
	a.tcpConnsMu.Lock()
	conn, exists := a.tcpConns[frame.ConnID]
	if exists {
		delete(a.tcpConns, frame.ConnID)
	}
	a.tcpConnsMu.Unlock()

	// Clean up any pending buffered data for this connection
	a.tcpPendingMu.Lock()
	_, hadPending := a.tcpPendingData[frame.ConnID]
	if hadPending {
		delete(a.tcpPendingData, frame.ConnID)
		log.Printf("TCP: Cleared buffered data for disconnected connection | ConnID: %s", frame.ConnID)
	}
	a.tcpPendingMu.Unlock()

	if exists {
		conn.Close()
		log.Printf("TCP: Closed local connection | ConnID: %s | Reason: %s", frame.ConnID, frame.Reason)
	} else {
		log.Printf("TCP: Disconnect received for unknown connection | ConnID: %s | Reason: %s", frame.ConnID, frame.Reason)
	}
}

// Delegation functions for connection.go

// handleTcpConnectNew processes TCP connect messages from the server (delegation)
func (a *Agent) handleTcpConnectNew(data []byte, writeEncrypted func(v any) error) {
	var frame TcpConnectFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse TCP connect frame: %v", err)
		return
	}
	ctx := context.Background()
	a.handleTcpConnect(ctx, &frame, writeEncrypted)
}

// handleTcpDataNew processes TCP data messages from the server (delegation)
func (a *Agent) handleTcpDataNew(data []byte, writeEncrypted func(v any) error) {
	var frame TcpDataFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse TCP data frame: %v", err)
		return
	}
	a.handleTcpData(&frame)
}

// handleTcpDisconnectNew processes TCP disconnect messages from the server (delegation)
func (a *Agent) handleTcpDisconnectNew(data []byte, writeEncrypted func(v any) error) {
	var frame TcpDisconnectFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		log.Printf("Failed to parse TCP disconnect frame: %v", err)
		return
	}
	a.handleTcpDisconnect(&frame)
}
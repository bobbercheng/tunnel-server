package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

func main() {
	publicURL := flag.String("public-url", "", "The public URL of the tunnel to connect to")
	localPort := flag.String("local-port", "8081", "The local port to listen on")
	flag.Parse()

	if *publicURL == "" {
		fmt.Println("The --public-url flag is required.")
		os.Exit(1)
	}

	targetURL, err := url.Parse(*publicURL)
	if err != nil {
		log.Fatalf("Invalid public URL: %v", err)
	}

	// Determine protocol type based on URL path
	if strings.Contains(targetURL.Path, "/__tcp__/") {
		// TCP tunnel mode
		log.Printf("Detected TCP tunnel: %s", *publicURL)
		startTcpProxy(*publicURL, *localPort)
	} else {
		// HTTP tunnel mode (default)
		log.Printf("Detected HTTP tunnel: %s", *publicURL)
		startHttpProxy(*publicURL, *localPort)
	}
}

func startHttpProxy(publicURL, localPort string) {
	targetURL, err := url.Parse(publicURL)
	if err != nil {
		log.Fatalf("Invalid public URL: %v", err)
	}

	// Extract the base URL and tunnel path
	baseURL := &url.URL{
		Scheme: targetURL.Scheme,
		Host:   targetURL.Host,
	}
	tunnelPath := targetURL.Path // This should be /__pub__/{id}

	proxy := httputil.NewSingleHostReverseProxy(baseURL)

	// Modify the director to preserve the tunnel path
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = baseURL.Scheme
		req.URL.Host = baseURL.Host
		// Prepend the tunnel path to the request path
		req.URL.Path = strings.TrimSuffix(tunnelPath, "/") + req.URL.Path
		req.Host = baseURL.Host

		log.Printf("HTTP: Forwarding %s %s to %s%s", req.Method, req.URL.Path, baseURL, req.URL.Path)
	}

	// Handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("HTTP Proxy error: %v", err)
		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusBadGateway)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	listenAddr := ":" + localPort
	log.Printf("Starting HTTP reverse proxy server on %s", listenAddr)
	log.Printf("Forwarding HTTP requests to %s", publicURL)
	log.Printf("Make sure the agent for this tunnel is connected to the server!")

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func startTcpProxy(publicURL, localPort string) {
	listenAddr := ":" + localPort
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("Starting TCP reverse proxy server on %s", listenAddr)
	log.Printf("Forwarding TCP connections to %s", publicURL)
	log.Printf("Make sure the agent for this tunnel is connected to the server!")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTcpConnection(conn, publicURL)
	}
}

func handleTcpConnection(localConn net.Conn, publicURL string) {
	defer localConn.Close()

	// Convert HTTP(S) URL to WebSocket URL
	wsURL := strings.Replace(publicURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)

	// Establish WebSocket connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		log.Printf("Failed to connect to WebSocket TCP tunnel: %v", err)
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "connection closed")

	log.Printf("TCP: Established WebSocket tunnel connection")

	// Handle bidirectional data flow using WebSocket binary messages
	done := make(chan struct{}, 2)

	// Forward data from local connection to tunnel (via WebSocket)
	go func() {
		defer func() {
			done <- struct{}{}
		}()

		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from local connection: %v", err)
				}
				return
			}

			if n == 0 {
				continue
			}

			// Send data as WebSocket binary message
			if err := ws.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
				log.Printf("Error writing to WebSocket tunnel: %v", err)
				return
			}
		}
	}()

	// Forward data from tunnel to local connection (via WebSocket)
	go func() {
		defer func() {
			done <- struct{}{}
		}()

		for {
			msgType, data, err := ws.Read(ctx)
			if err != nil {
				if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
					log.Printf("Error reading from WebSocket tunnel: %v", err)
				}
				return
			}

			// We expect binary messages for TCP data
			if msgType != websocket.MessageBinary {
				log.Printf("Unexpected WebSocket message type: %v", msgType)
				continue
			}

			if _, err := localConn.Write(data); err != nil {
				log.Printf("Error writing to local connection: %v", err)
				return
			}
		}
	}()

	// Wait for either direction to close
	<-done
	log.Printf("TCP: Connection closed")
}

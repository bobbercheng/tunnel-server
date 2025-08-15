package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Global state and configuration
var (
	// Agent connections
	agents   = make(map[string]*agentConn) // id -> connection
	agentsMu sync.RWMutex

	// Tunnel metadata (for stateless Cloud Run)
	tunnels   = make(map[string]*TunnelInfo) // id -> tunnel info
	tunnelsMu sync.RWMutex

	// Custom URL mappings (case-sensitive)
	customURLs   = make(map[string]string) // custom_url -> tunnel_id
	customURLsMu sync.RWMutex

	// Client tracking for smart routing
	clientTracker = NewClientTracker()
)

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
	mux.HandleFunc("/__register__", registerHandler)
	mux.HandleFunc("/__ws__", wsHandler) // agent websocket
	mux.HandleFunc("/__pub__/", publicHandler)
	mux.HandleFunc("/__tcp__/", tcpHandler)
	mux.HandleFunc("/__health__", healthHandler)
	// Custom URL handler with smart fallback - must be last (catch-all)
	mux.HandleFunc("/", customURLHandler)

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
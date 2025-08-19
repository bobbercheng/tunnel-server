package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)


func main() {
	// Initialize global components
	clientTracker = NewClientTracker()
	affinityManager = NewAffinityManager()
	log.Println("Initialized custom URL affinity manager")

	// Validate and cleanup any stale connections from previous server instance
	log.Println("Performing connection validation on startup...")
	validateAndCleanupStaleConnections()

	// Start periodic connection validation routine
	schedulePeriodicConnectionValidation()

	// Start client tracker cleanup routine
	go func() {
		ticker := time.NewTicker(clientTracker.cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			clientTracker.CleanupExpiredSessions()
		}
	}()

	// Start recent mappings cleanup routine (more frequent for 2-second window)
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Clean every 10 seconds
		defer ticker.Stop()

		for range ticker.C {
			clientTracker.CleanupExpiredRecentMappings()
		}
	}()

	// Start affinity cleanup routine (less frequent for long-term affinities)
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Clean every hour
		defer ticker.Stop()

		for range ticker.C {
			affinityManager.CleanupInactiveAffinities(24 * time.Hour) // Remove affinities unused for 24+ hours
			affinityManager.CleanupDisconnectedTunnels()              // Remove affinities for disconnected tunnels
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/__ws__", wsHandler) // agent websocket
	mux.HandleFunc("/__pub__/", publicHandler)
	mux.HandleFunc("/__tcp__/", tcpHandler)
	mux.HandleFunc("/__health__", healthHandler)
	mux.Handle("/__metrics__", promhttp.Handler()) // Prometheus metrics endpoint
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

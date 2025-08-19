package main

import (
	"sync"
	"tunnel.local/metrics"
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
	clientTracker *ClientTracker

	// Custom URL affinity manager
	affinityManager *AffinityManager

	// Metrics for usage tracking
	tunnelMetrics = metrics.NewTunnelMetrics()
)
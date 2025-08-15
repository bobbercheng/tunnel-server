package main

import (
	"sync"
	"time"

	crypto "tunnel.local/crypto"

	"nhooyr.io/websocket"
)

// Request and response frame types for the WebSocket protocol
type RegisterReq struct {
	Protocol  string `json:"protocol"`           // "http" or "tcp"
	Port      int    `json:"port"`               // for TCP tunnels, the local port being tunneled
	CustomURL string `json:"custom_url,omitempty"` // custom URL like "bob/chatbot"
}

type RegisterResp struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`        // Default /__pub__/{id} or /__tcp__/{id}
	CustomURL string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol  string `json:"protocol"`
	TcpPort   int    `json:"tcp_port,omitempty"` // for TCP tunnels
}

type ReqFrame struct {
	Type    string              `json:"type"` // "req"
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type RespFrame struct {
	Type    string              `json:"type"` // "resp"
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// ChunkedRespFrame represents a chunked response for large files
type ChunkedRespFrame struct {
	Type        string              `json:"type"` // "chunked_resp"
	ReqID       string              `json:"req_id"`
	Status      int                 `json:"status"`  // Only set in first chunk
	Headers     map[string][]string `json:"headers"` // Only set in first chunk
	ChunkIndex  int                 `json:"chunk_index"`
	TotalChunks int                 `json:"total_chunks"`
	Data        []byte              `json:"data"`
	IsLast      bool                `json:"is_last"`
}

// HandshakeFrame is used for initial key exchange
type HandshakeFrame struct {
	Type string `json:"type"` // "handshake"
	Salt string `json:"salt"` // base64 encoded salt
}

// TCP Frame types for raw TCP tunneling
type TcpConnectFrame struct {
	Type   string `json:"type"`    // "tcp_connect"
	ConnID string `json:"conn_id"` // unique connection identifier
	Port   int    `json:"port"`    // destination port
}

type TcpDataFrame struct {
	Type   string `json:"type"`    // "tcp_data"
	ConnID string `json:"conn_id"` // connection identifier
	Data   []byte `json:"data"`    // raw TCP data
}

type TcpDisconnectFrame struct {
	Type   string `json:"type"`    // "tcp_disconnect"
	ConnID string `json:"conn_id"` // connection identifier
	Reason string `json:"reason"`  // disconnect reason
}

// Ping/Pong frames for connection health monitoring
type PingFrame struct {
	Type      string    `json:"type"`      // "ping"
	Timestamp time.Time `json:"timestamp"` // when ping was sent
}

type PongFrame struct {
	Type      string    `json:"type"`      // "pong"
	Timestamp time.Time `json:"timestamp"` // original ping timestamp
}

// TunnelInfoFrame is sent by agent to provide tunnel details during reconnection
type TunnelInfoFrame struct {
	Type     string `json:"type"`     // "tunnel_info"
	Protocol string `json:"protocol"` // "http" or "tcp"
	Port     int    `json:"port"`     // for TCP tunnels
}

// Agent connection tracking
type agentConn struct {
	id          string
	secret      string
	ws          *websocket.Conn
	cipher      *crypto.StreamCipher
	connectedAt time.Time

	writeMu sync.Mutex

	// reqID -> channel to deliver response (for HTTP)
	respMu  sync.Mutex
	waiters map[string]chan *RespFrame

	// TCP connection management
	tcpConnsMu sync.Mutex
	tcpConns   map[string]*TcpConn // connID -> TcpConn

	// Chunked response management
	chunkedMu        sync.Mutex
	chunkedResponses map[string]*ChunkedResponse // reqID -> ChunkedResponse

	// Connection health monitoring
	lastPong time.Time
	pingMu   sync.RWMutex
}

// ChunkedResponse tracks assembly of chunked responses
type ChunkedResponse struct {
	ReqID       string
	Status      int
	Headers     map[string][]string
	Chunks      map[int][]byte // chunkIndex -> data
	TotalChunks int
	Received    int
	LastSeen    time.Time
}

// TcpConn represents an active TCP connection through the tunnel
type TcpConn struct {
	id      string
	dataCh  chan []byte
	closeCh chan string
	closed  bool
	closeMu sync.Mutex
}

// Tunnel metadata
type TunnelInfo struct {
	Secret    string    `json:"secret"`
	Protocol  string    `json:"protocol"`           // "http" or "tcp"
	Port      int       `json:"port"`               // for TCP tunnels
	Created   time.Time `json:"created"`            // when tunnel was created
	CustomURL string    `json:"custom_url,omitempty"` // custom URL if set
}

// Client tracking and fingerprinting types
type ClientFingerprint struct {
	// Core identification
	ClientIP      string
	UserAgent     string
	SessionCookie string

	// Authentication signals
	Authorization string            // Hashed authorization header
	AuthCookies   map[string]string // Hashed auth-related cookies
	SessionTokens map[string]string // Hashed custom session headers

	// Browser fingerprinting
	AcceptLanguage string
	AcceptEncoding string
	AcceptCharset  string
	DNT            string // Do Not Track

	// Network & Infrastructure
	XForwardedFor  string
	XRealIP        string
	XClientIP      string
	CFConnectingIP string // Cloudflare
	XOriginalHost  string

	// Application-specific
	Origin  string
	Referer string
	Host    string

	// Browser capabilities
	Connection   string
	CacheControl string
	Pragma       string

	// Framework and device info
	CustomHeaders map[string]string

	// Computed fingerprint
	FingerprintHash string
	Confidence      float64
	CreatedAt       time.Time
}

// ClientSession tracks a client's tunnel mapping history
type ClientSession struct {
	ID             string
	Fingerprint    *ClientFingerprint
	LastSeen       time.Time
	TunnelMappings map[string]int     // tunnelID -> usage_count
	SuccessRate    map[string]float64 // tunnelID -> success_rate
	Confidence     float64            // Overall routing confidence
}

// ClientTracker manages client sessions and tunnel mappings
type ClientTracker struct {
	// Primary tracking
	clientSessions map[string]*ClientSession // clientKey -> session
	ipMappings     map[string][]string       // clientIP -> clientKeys
	tunnelClients  map[string][]string       // tunnelID -> clientKeys

	// Performance optimization
	recentMappings map[string]string // clientKey -> tunnelID (LRU-like)

	// Configuration
	maxSessions     int
	sessionTTL      time.Duration
	cleanupInterval time.Duration

	// Thread safety
	mu sync.RWMutex
}

// FingerprintConfig holds configuration for fingerprint extraction
type FingerprintConfig struct {
	// Header priorities
	AuthHeaderPriority    []string
	SessionCookiePatterns []string
	SessionHeaderPatterns []string
	IPHeaderPriority      []string

	// Confidence weights
	AuthWeight    float64
	SessionWeight float64
	IPWeight      float64
	BrowserWeight float64

	// Privacy settings
	HashSensitiveData bool
	MaxFingerprintAge time.Duration
}

// Geographical routing types
type IPGeoData struct {
	Country   string    `json:"country"`
	Region    string    `json:"region"`
	CacheTime time.Time `json:"cache_time"`
}

type IPTunnelMapping struct {
	IPAddress    string    `json:"ip_address"`
	LastTunnelID string    `json:"last_tunnel_id"`
	LastSuccess  time.Time `json:"last_success"`
	UsageCount   int       `json:"usage_count"`
	SuccessRate  float64   `json:"success_rate"`
}

type GeoTunnelPreference struct {
	TunnelID    string    `json:"tunnel_id"`
	UsageCount  int       `json:"usage_count"`
	SuccessRate float64   `json:"success_rate"`
	LastUsed    time.Time `json:"last_used"`
}

// discardResponseWriter is used for testing tunnel responses without writing to the real response
type discardResponseWriter struct {
	headers map[string][]string
	status  int
}
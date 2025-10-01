package agentlib

import (
	"regexp"
	"sync"
	"time"
)

// WebSocketFrame is used for WebSocket frame forwarding
type WebSocketFrame struct {
	Type        string `json:"type"`         // "websocket_frame" or "websocket_close"
	ReqID       string `json:"req_id"`       // request identifier
	MessageType int    `json:"message_type"` // WebSocket message type (text, binary, etc.)
	Data        []byte `json:"data"`         // frame data
	Direction   string `json:"direction"`    // "to_server" or "to_client"
}

type RegisterResp struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	PublicURL   string `json:"public_url"`
	CustomURL   string `json:"custom_url,omitempty"` // custom URL if requested
	Protocol    string `json:"protocol"`
	TcpPort     int    `json:"tcp_port,omitempty"`     // for TCP tunnels
	UseRedirect bool   `json:"use_redirect,omitempty"` // redirection enabled
}

type ReqFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type RespFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type ChunkedRespFrame struct {
	Type        string              `json:"type"` // "chunked_resp"
	ReqID       string              `json:"req_id"`
	Status      int                 `json:"status"`
	Headers     map[string][]string `json:"headers"`
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

// RegisterFrame is used for agent registration over WebSocket (encrypted)
type RegisterFrame struct {
	Type        string `json:"type"`                   // "register"
	Protocol    string `json:"protocol"`               // "http" or "tcp"
	Port        int    `json:"port"`                   // for TCP tunnels, the local port being tunneled
	CustomURL   string `json:"custom_url,omitempty"`   // custom URL like "bob/chatbot"
	UseRedirect bool   `json:"use_redirect,omitempty"` // enable SPA redirection
}

// RegisterResponseFrame is the server's response to registration (encrypted)
type RegisterResponseFrame struct {
	Type        string `json:"type"` // "register_response"
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	PublicURL   string `json:"public_url"`
	CustomURL   string `json:"custom_url,omitempty"`
	UseRedirect bool   `json:"use_redirect,omitempty"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// TCP tunnel frames
type TcpConnectFrame struct {
	Type    string `json:"type"`
	ConnID  string `json:"conn_id"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type TcpDataFrame struct {
	Type   string `json:"type"`
	ConnID string `json:"conn_id"`
	Data   []byte `json:"data"`
}

type TcpDisconnectFrame struct {
	Type   string `json:"type"`
	ConnID string `json:"conn_id"`
	Reason string `json:"reason,omitempty"`
}

type TcpConnectRespFrame struct {
	Type    string `json:"type"`
	ConnID  string `json:"conn_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// HeartbeatFrame for connection monitoring
type HeartbeatFrame struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// Streaming response management
type ChunkedResponse struct {
	Status            int
	Headers           map[string][]string
	ChunkIndex        int
	TotalChunks       int
	Chunks            [][]byte
	ReceivedChunks    map[int][]byte
	ReceivedCount     int
	Complete          bool
	mu                sync.Mutex
}

// Request queue management
type PendingRequest struct {
	ReqFrame    *ReqFrame
	ResponseCh  chan *RespFrame
	CreatedAt   time.Time
	RetriesLeft int
	IsHTTP      bool
}

// Content rewriting configuration
type RewriteConfig struct {
	Rules []RewriteRule `json:"rules"`
}

type RewriteRule struct {
	Name         string   `json:"name"`
	MatchDomain  string   `json:"match_domain"`
	MatchPath    string   `json:"match_path"`
	Pattern      string   `json:"pattern"`
	Replacement  string   `json:"replacement"`
	ContentTypes []string `json:"content_types"`
	Enabled      bool     `json:"enabled"`
	Actions      []Action `json:"actions"`

	// Runtime fields (not JSON serialized)
	compiledRegex *regexp.Regexp `json:"-"`
}

type Action struct {
	Type       string            `json:"type"`
	Pattern    string            `json:"pattern,omitempty"`
	Replace    string            `json:"replace,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
}

// Agent statistics and state
type AgentStats struct {
	RequestsProcessed int64     `json:"requests_processed"`
	BytesTransferred  int64     `json:"bytes_transferred"`
	ConnectionStart   time.Time `json:"connection_start"`
	LastActivity      time.Time `json:"last_activity"`
}

// Proxy frames for HTTP proxy functionality
type ProxyReqFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type ProxyRespFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}
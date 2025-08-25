# AgentLib - Tunnel Agent Library

A Go library that provides the core functionality for HTTP/TCP tunnel agents that connect to remote tunnel servers through encrypted WebSocket connections.

## Overview

AgentLib implements a transparent proxy agent that:
- Connects to tunnel servers via encrypted WebSocket
- Forwards HTTP/TCP requests to local services
- Maintains session persistence and connection health
- Provides browser-like HTTP client behavior for bot detection bypass

## Features

### 🔒 **Secure Communication**
- **ChaCha20-Poly1305** encryption for all WebSocket messages
- **HKDF-based key derivation** with per-session salts
- **TLS 1.2/1.3** support with modern cipher suites
- **Separate send/receive keys** for bidirectional security

### 🌐 **Protocol Support**
- **HTTP Tunneling**: Forward HTTP requests with streaming support
- **TCP Tunneling**: Raw TCP connection forwarding
- **WebSocket Tunneling**: Bidirectional WebSocket frame forwarding
- **Custom URLs**: Human-readable URLs instead of UUIDs

### 🤖 **Browser-Like HTTP Client**
- **Realistic TLS fingerprinting** matching Chrome/Firefox
- **Dynamic User-Agent rotation** from real browser strings
- **Complete browser headers** (Sec-CH-UA, Sec-Fetch-*, Accept-*, etc.)
- **Cookie jar** for session persistence
- **Connection pooling** with browser-like behavior
- **Conditional header application** (external vs localhost)

### 🔄 **Connection Management**
- **Auto-reconnection** with exponential backoff
- **Connection health monitoring** via ping/pong
- **Request queuing** during connection recovery
- **Graceful degradation** with multiple retry strategies

### 📊 **Advanced Features**
- **Streaming response handling** with real-time chunking
- **Session affinity** for multi-request workflows
- **Geographic routing** support
- **SPA redirection** for Single Page Applications
- **Request/response metrics** and logging

## Usage

### Basic HTTP Tunnel

```go
agent := &agentlib.Agent{
    ServerURL:   "https://tunnel-server.example.com",
    LocalURL:    "http://localhost:8080",
    Protocol:    "http",
    CustomURL:   "my-app",
    UseRedirect: true,
}

agent.InitializeQueue()
agent.Run() // Blocks and maintains connection
```

### TCP Tunnel

```go
agent := &agentlib.Agent{
    ServerURL: "https://tunnel-server.example.com",
    LocalURL:  "tcp://localhost:3306",
    Protocol:  "tcp",
    Port:      3306,
}

agent.InitializeQueue()
agent.Run()
```

### Existing Tunnel Reconnection

```go
agent := &agentlib.Agent{
    ServerURL: "https://tunnel-server.example.com",
    LocalURL:  "http://localhost:8080",
    ID:        "existing-tunnel-id",
    Secret:    "tunnel-secret",
    Protocol:  "http",
}

agent.InitializeQueue()
agent.Run()
```

## Architecture

### Agent Structure

```go
type Agent struct {
    // Connection Configuration
    ServerURL   string // Tunnel server URL
    LocalURL    string // Local service URL
    ID          string // Tunnel identifier
    Secret      string // Authentication secret
    Protocol    string // "http" or "tcp"
    Port        int    // TCP port (for TCP tunnels)
    CustomURL   string // Human-readable URL path
    UseRedirect bool   // Enable SPA redirection

    // Browser Client (for HTTP)
    browserClient *http.Client // Browser-configured HTTP client
    cookieJar     http.CookieJar // Session cookie storage
    
    // Connection State
    isConnected bool // Current connection status
    lastPong    time.Time // Health monitoring
    
    // Request Management
    requestQueue []*PendingRequest // Connection recovery queue
    
    // Response Handling
    chunkedResps  map[string]*ChunkedResponse // Streaming responses
    streamingResps map[string]*http.Response  // Active streams
    
    // TCP Connections
    tcpConns map[string]net.Conn // Active TCP connections
}
```

### Message Types

#### HTTP Messages
```go
// Request from server to agent
type ReqFrame struct {
    Type    string              `json:"type"`
    ReqID   string              `json:"req_id"`
    Method  string              `json:"method"`
    Path    string              `json:"path"`
    Query   string              `json:"query"`
    Headers map[string][]string `json:"headers"`
    Body    []byte              `json:"body"`
}

// Response from agent to server
type RespFrame struct {
    Type    string              `json:"type"`
    ReqID   string              `json:"req_id"`
    Status  int                 `json:"status"`
    Headers map[string][]string `json:"headers"`
    Body    []byte              `json:"body"`
}
```

#### WebSocket Messages
```go
type WebSocketFrame struct {
    Type        string `json:"type"`         // "websocket_frame" or "websocket_close"
    ReqID       string `json:"req_id"`       // Request identifier
    MessageType int    `json:"message_type"` // WebSocket message type
    Data        []byte `json:"data"`         // Frame data
    Direction   string `json:"direction"`    // "to_server" or "to_client"
}
```

#### TCP Messages
```go
type TcpConnectFrame struct {
    Type   string `json:"type"`    // "tcp_connect"
    ConnID string `json:"conn_id"` // Connection identifier
    Port   int    `json:"port"`    // Destination port
}

type TcpDataFrame struct {
    Type   string `json:"type"`    // "tcp_data"
    ConnID string `json:"conn_id"` // Connection identifier
    Data   []byte `json:"data"`    // Raw TCP data
}
```

## Browser Client Features

### TLS Configuration
- **Modern cipher suites** matching Chrome/Firefox preferences
- **TLS 1.2/1.3** with proper version negotiation
- **Connection pooling** with realistic idle timeouts
- **HTTP/2 support** with proper SETTINGS frames

### Header Management
- **Dynamic User-Agent** rotation from real browser strings
- **Complete browser headers** including:
  - `Accept`: Full content type negotiation
  - `Accept-Language`: Locale preferences
  - `Accept-Encoding`: Compression support
  - `Sec-CH-UA-*`: Client hints
  - `Sec-Fetch-*`: Request context
  - `Cache-Control`: Browser caching behavior
  - `DNT`: Privacy preferences (random)

### Session Persistence
- **Cookie jar** maintains authentication state
- **Connection reuse** for multiple requests
- **Redirect handling** up to 10 redirects
- **Session affinity** across request chains

## Error Handling

### Connection Errors
```go
var (
    ErrUnauthorized   = errors.New("unauthorized: credentials rejected by server")
    ErrNetworkFailure = errors.New("network failure: unable to reach server")
    ErrDNSFailure     = errors.New("dns failure: unable to resolve server hostname")
    ErrTunnelMismatch = errors.New("tunnel mismatch: server expects different tunnel ID")
)
```

### Retry Strategies
- **DNS failures**: 5-60 second exponential backoff
- **Network failures**: 3-30 second exponential backoff
- **Authentication failures**: Immediate re-registration
- **Tunnel mismatches**: Immediate re-registration

### Request Recovery
- **Queue up to 100 requests** during disconnection
- **30-second request timeout** before expiration
- **Automatic replay** when connection restored
- **Graceful degradation** for failed requests

## Configuration

### Environment Variables
- `AGENT_LOG_LEVEL`: Set logging verbosity
- `AGENT_TIMEOUT`: Override default timeouts
- `AGENT_RETRY_COUNT`: Maximum retry attempts

### Advanced Options
```go
// Custom browser client configuration
agent.InitializeQueue()

// Override default queue size
agent.maxQueueSize = 200

// Custom timeout settings  
agent.queueTimeout = 60 * time.Second
```

## Testing

### Unit Tests
```bash
go test ./pkg/agentlib
```

### Integration Tests
```bash
# Test with streaming
go test -v ./pkg/agentlib -run TestStreaming

# Test ping/pong health
go test -v ./pkg/agentlib -run TestPingPong
```

### Manual Testing
```bash
# Start agent with debug logging
go run ./agent --local http://localhost:8080 --custom-url test --debug

# Test browser headers
curl -s https://tunnel-server.com/__pub__/tunnel-id/headers | jq .headers
```

## Limitations

- **Single-instance server**: In-memory state requires server affinity
- **1MB message limit**: Large requests/responses are chunked
- **Browser detection**: Advanced systems may still detect automation
- **Memory usage**: Session state grows with active connections

## Dependencies

- `nhooyr.io/websocket`: WebSocket client implementation  
- `tunnel.local/crypto`: ChaCha20-Poly1305 encryption
- Standard Go libraries: `net/http`, `crypto/tls`, `net/http/cookiejar`

## License

Part of the GCP Proxy tunnel system.
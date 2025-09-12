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
- **HTTP Proxy Support**: Act as HTTP proxy destination for external requests
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
- **Content rewriting** for HTML/JS/CSS URL replacement
- **Header rewriting** for CORS and security headers
- **Request/response metrics** and logging

## Usage

### Basic HTTP Tunnel

```go
agent := &agentlib.Agent{
    ServerURL:      "https://tunnel-server.example.com",
    LocalURL:       "http://localhost:8080",
    Protocol:       "http",
    CustomURL:      "my-app",
    UseRedirect:    true,
    RewriteContent: false, // Optional: enable URL rewriting
    RewriteHeaders: false, // Optional: enable CORS header rewriting
}

agent.InitializeQueue()
agent.Run() // Blocks and maintains connection
```

### HTTP Tunnel with Content Rewriting

```go
agent := &agentlib.Agent{
    ServerURL:      "https://tunnel-server.example.com",
    LocalURL:       "http://localhost:8080",
    Protocol:       "http",
    CustomURL:      "my-app",
    UseRedirect:    true,
    RewriteContent: true,  // Enable content rewriting
    RewriteHeaders: true,  // Enable header rewriting
}

agent.InitializeQueue()

// Load custom rewrite rules (optional)
err := agent.LoadRewriteConfig("custom-rules.json")
if err != nil {
    // Falls back to default rules if file loading fails
    log.Printf("Using default rewrite rules: %v", err)
}

agent.Run()
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

## Content Rewriting Configuration

The agent supports user-configurable content rewriting to replace URLs in HTML, JavaScript, CSS, and JSON responses. This ensures all requests route through the tunnel properly.

### Default Rules

When content rewriting is enabled (`RewriteContent: true`), the agent automatically applies default rules based on the original domain extracted from `LocalURL`:

```go
// Default rules are generated automatically
agent := &agentlib.Agent{
    LocalURL: "https://chatgpt.com",  // Original domain: chatgpt.com
    // ...
    RewriteContent: true,
}
// Automatically creates rules to replace chatgpt.com → tunnel-domain.com
```

### Custom Rewrite Rules

For advanced scenarios, you can define custom rewrite rules in a JSON configuration file:

```json
{
  "rules": [
    {
      "name": "basic-url-replacement",
      "pattern": "https://chatgpt\\.com",
      "replacement": "https://connect.vexorium.net",
      "content_types": ["text/html", "application/javascript", "text/css"],
      "enabled": true
    },
    {
      "name": "javascript-fetch-calls",
      "pattern": "fetch\\s*\\(\\s*[\"']https://chatgpt\\.com(/[^\"']*)?[\"']",
      "replacement": "fetch(\"https://connect.vexorium.net$1\"",
      "content_types": ["application/javascript"],
      "enabled": true
    },
    {
      "name": "css-url-function",
      "pattern": "url\\s*\\(\\s*[\"']?https://chatgpt\\.com(/[^\"'\\)]*)?[\"']?\\s*\\)",
      "replacement": "url(\"https://connect.vexorium.net$1\")",
      "content_types": ["text/css", "text/html"],
      "enabled": false
    }
  ]
}
```

### Rule Configuration Fields

- **name**: Human-readable identifier for the rule
- **pattern**: Regular expression pattern to match (uses Go regex syntax)
- **replacement**: Replacement template (supports capture groups `$1`, `$2`, etc.)
- **content_types**: Array of MIME types where this rule applies
- **enabled**: Boolean to toggle the rule on/off

### Content Type Matching

Rules are applied only to responses with matching Content-Type headers:

- **text/html**: Web pages, HTML fragments
- **application/javascript**: JavaScript files, API responses
- **text/css**: Stylesheets, CSS files
- **application/json**: JSON API responses, configuration files
- **text/plain**: Plain text (sometimes used for JavaScript)

### Command-Line Usage

```bash
# Use default rules
./agent-bin --rewrite-content --local https://chatgpt.com

# Use custom rules file
./agent-bin --rewrite-content --rewrite-rules-file custom-rules.json --local https://chatgpt.com

# Enable both content and header rewriting
./agent-bin --rewrite-content --rewrite-headers --local https://chatgpt.com
```

### Regex Pattern Examples

Common patterns for different scenarios:

```json
{
  "rules": [
    {
      "name": "absolute-urls",
      "pattern": "https://example\\.com(/[^\"'\\s\\)>]*)?",
      "replacement": "https://tunnel.example.com$1"
    },
    {
      "name": "api-endpoints",
      "pattern": "\"/api/([^\"]*)",
      "replacement": "\"https://tunnel.example.com/api/$1"
    },
    {
      "name": "javascript-variables",
      "pattern": "(const|let|var)\\s+(\\w+)\\s*=\\s*[\"']https://example\\.com[\"']",
      "replacement": "$1 $2 = \"https://tunnel.example.com\""
    }
  ]
}
```

### Performance Considerations

- Rules are compiled once at startup for optimal performance
- Only enabled rules matching the content type are processed
- Rules are applied in the order they appear in the configuration
- Large rule sets may impact response latency for text-heavy content

### Debugging Rewrite Rules

Enable detailed logging to debug rule matching:

```bash
AGENT_LOG_LEVEL=debug ./agent-bin --rewrite-content --rewrite-rules-file debug-rules.json
```

Log output shows which rules matched and what replacements were made:

```
REWRITE: Applied rule 'basic-url-replacement' | Matches: 3 | Patterns: [...] | ReqID: abc123
REWRITE SUCCESS: Content modified | Original: 1024 bytes → Rewritten: 1056 bytes | Total matches: 5
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
    Protocol       string // "http" or "tcp"
    Port           int    // TCP port (for TCP tunnels)
    CustomURL      string // Human-readable URL path
    UseRedirect    bool   // Enable SPA redirection
    RewriteContent bool   // Enable content rewriting for HTML/JS/CSS
    RewriteHeaders bool   // Enable response header rewriting for CORS
    RewriteConfig  *RewriteConfig // User-defined rewriting rules

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

### Rewrite Configuration Types

```go
// RewriteRule defines a user-configurable content rewriting pattern
type RewriteRule struct {
    Name         string   `json:"name"`          // Human-readable rule name
    Pattern      string   `json:"pattern"`       // Regex pattern to match
    Replacement  string   `json:"replacement"`   // Replacement template (supports $1, $2, etc.)
    ContentTypes []string `json:"content_types"` // Apply only to these content types
    Enabled      bool     `json:"enabled"`       // Toggle rule on/off
}

// RewriteConfig holds the complete rewriting configuration
type RewriteConfig struct {
    Rules []RewriteRule `json:"rules"` // List of rewrite rules
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

#### HTTP Proxy Messages
```go
// Proxy request from server to agent
type ProxyReqFrame struct {
    Type     string              `json:"type"`     // "proxy_req"
    ReqID    string              `json:"req_id"`   // unique request identifier
    Method   string              `json:"method"`   // HTTP method (GET, POST, etc.)
    URL      string              `json:"url"`      // Full target URL to request
    Headers  map[string][]string `json:"headers"`  // HTTP headers
    Body     []byte              `json:"body"`     // Request body
}

// Proxy response from agent to server
type ProxyRespFrame struct {
    Type     string              `json:"type"`     // "proxy_resp"
    ReqID    string              `json:"req_id"`   // request identifier
    Status   int                 `json:"status"`   // HTTP status code
    Headers  map[string][]string `json:"headers"`  // Response headers
    Body     []byte              `json:"body"`     // Response body
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
# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go-based reverse-tunnel HTTP proxy system with two main components:
- **Server**: Cloud Run service that exposes public endpoints and manages WebSocket connections
- **Agent**: Client that runs near internal services and maintains persistent WebSocket to server

The system uses encrypted WebSocket communication with ChaCha20-Poly1305 for secure data transmission between server and agent.

## Architecture

### Multi-module Structure
- Uses Go workspaces (`go.work`) to manage multiple modules
- **server/**: Cloud Run service (handles `/__register__`, `/__ws__`, `/__pub__/`, `/__tcp__/`, `/__health__`)
- **agent/**: Client binary that connects to server and forwards to local services
- **reverse-proxy-agent/**: Alternative client that acts as HTTP/TCP proxy for local connections
- **pkg/agentlib/**: Shared agent logic library (modularized architecture)
- **pkg/crypto/**: Encryption/decryption utilities with ChaCha20-Poly1305
- **pkg/metrics/**: Metrics collection and reporting utilities

### Modular agentlib Architecture (Key Innovation)
The `pkg/agentlib/` package has been refactored from a monolithic 3,156-line file into focused modules:

- **agent.go** (177 lines) - Core coordination and delegation only
- **connection.go** (155 lines) - WebSocket handshake and message routing
- **http_forwarder.go** (319 lines) - HTTP request forwarding and response handling
- **tcp_handler.go** (174 lines) - TCP tunnel connection management
- **websocket_handler.go** (258 lines) - WebSocket upgrade and bidirectional forwarding
- **streaming.go** (252 lines) - Chunked and streaming response management
- **registration.go** (210 lines) - Agent registration and credential management
- **rewriter.go** (402 lines) - Content rewriting for URL transformation
- **client.go** (301 lines) - uTLS browser client creation and HTTP client setup
- **debug.go** (168 lines) - Debug logging to files with request/response tracing
- **queue.go** (97 lines) - Request queue management for connection recovery
- **types.go** (188 lines) - All frame types and data structures
- **utils.go** (69 lines) - Utility functions and error classification

**Critical Design Principle**: `agent.go` contains only coordination logic and delegates all implementation to modular components. Each module has a single responsibility and can be modified independently.

### Key Components
- **WebSocket Protocol**: JSON messages over encrypted WebSocket (server→agent: ReqFrame, agent→server: RespFrame)
- **Key Exchange**: HKDF-based key derivation with per-session salts
- **Enhanced Smart Routing**: Multi-header client fingerprinting with learning capabilities for SPA asset routing
- **Client Tracker**: Intelligent client identification and tunnel mapping with adaptive learning
- **TCP Tunneling**: Support for raw TCP connections through WebSocket tunnels
- **Custom URLs**: Case-sensitive memorable URLs like `/bob/chatbot` instead of `/pub/{uuid}`
- **SPA Redirection**: Hybrid redirection system for React/Vue/Angular apps with session-based client tracking
- **In-memory State**: Server keeps tunnels and agent connections in memory (PoC limitation)

## Development Commands

### Building
```bash
# Build server (from workspace root)
cd server && go build -o ../server-bin

# Build agent (from workspace root)
cd agent && go build -o ../agent-bin

# Build reverse-proxy-agent (from workspace root)
cd reverse-proxy-agent && go build -o ../reverse-proxy-agent-bin

# Sync all workspace modules (run after pulling changes)
go work sync

# Build all modules to verify compilation
go build ./...

# Clean build artifacts
rm -f server-bin agent-bin reverse-proxy-agent-bin
```

### Running Locally
```bash
# Start server on default port 8080
cd server && go run .

# Start server with custom port
cd server && PORT=8081 go run .

# Start agent with HTTP tunneling (supports bare hostnames)
cd agent && go run . --server http://localhost:8080 --local localhost:3000
cd agent && go run . --server http://localhost:8080 --local http://127.0.0.1:3000

# Start agent with TCP tunneling (bare hostname or URL format both work)
cd agent && go run . --server http://localhost:8080 --local localhost --protocol tcp --port 3306
cd agent && go run . --server http://localhost:8080 --local tcp://127.0.0.1:3306 --protocol tcp --port 3306

# Start agent with custom URL and SPA redirection
cd agent && go run . --server http://localhost:8080 --local http://localhost:3000 --custom-url myapp --use-redirect

# Alternative: Use reverse-proxy-agent (acts as HTTP proxy destination)
cd reverse-proxy-agent && go run . --public-url <tunnel-url> --local-port 8081
```

### Testing
```bash
# Test all modules from workspace root
go test ./...

# Test with verbose output
go test -v ./...

# Test individual modules
cd server && go test ./...
cd pkg/agentlib && go test ./...
cd pkg/crypto && go test ./...

# Test specific file
cd server && go test -v -run TestSmartRouting

# Check for code issues
go vet ./...

# Run tests with race detector
go test -race ./...
```

### Deployment & Operations
```bash
# Deploy to GCP Cloud Run (recommended method)
cd server && ./deploy.sh

# View Cloud Run logs (default: last 100 lines)
cd server && ./logs.sh

# View logs with custom limit
cd server && ./logs.sh -l 1000

# View recent logs quickly (last 50 lines)
cd server && ./quick-logs.sh

# Restart Cloud Run service (zero-downtime)
cd server && ./restart.sh

# Build Docker image locally
cd server && docker build -f Dockerfile -t gcp-proxy-server ..
```

### Development Workflow for agentlib
When working with the modular agentlib:

```bash
# Always run from workspace root to ensure module resolution
go work sync

# Build specific module to check compilation
cd pkg/agentlib && go build

# Test agent integration after agentlib changes
cd agent && go build -o ../agent-bin
```

**Important**: When modifying agentlib modules, ensure `agent.go` only contains coordination logic and delegates to modular functions with "New" suffixes (e.g., `handleTcpConnectNew`, `logDebugRequestNew`).

## Protocol & Message Flow

### Connection Establishment
1. **Agent connects** to server WebSocket at `/__ws__`
2. **Handshake**: Server sends salt, agent ACKs → encryption established (ChaCha20-Poly1305)
3. **Registration**: Agent sends encrypted `RegisterFrame` with protocol/port info
4. **Response**: Server returns `{id, secret, public_url, custom_url}`
5. **Health monitoring**: Server sends ping every 15s, agent responds with pong (5min timeout)

### HTTP Tunneling Flow
1. **Public request** arrives at `/__pub__/{id}/path` or custom URL
2. **Server → Agent**: Encrypted `ReqFrame` with method, path, headers, body
3. **Agent → Local**: HTTP request forwarded to local service
4. **Local → Agent**: Response received
5. **Agent → Server**: Encrypted `RespFrame` with status, headers, body
6. **Server → Client**: Response proxied back to original requester

### TCP Tunneling Flow
1. **TCP connection** arrives at `/__tcp__/{id}` (raw TCP or WebSocket upgrade)
2. **Server → Agent**: `TcpConnectFrame` with connection ID and port
3. **Agent connects** to local TCP service (supports bare hostname format: `localhost` or URL format: `tcp://localhost:3306`)
4. **Bidirectional relay**: `TcpDataFrame` messages forward data in both directions
5. **Disconnect**: Either side sends `TcpDisconnectFrame` to close connection

### Smart Routing (SPA Asset Handling)
1. **Asset Request**: Browser requests `/assets/file.js` (missing tunnel prefix)
2. **Client Fingerprinting**: Multi-header analysis (IP, User-Agent, Accept-Language, etc.)
3. **Smart Routing**: Automatic redirect to `/__pub__/{detected-id}/assets/file.js`
4. **Learning**: System caches successful mappings for 2-second window

### Ping/Pong Health Monitoring
1. **Server sends**: `PingFrame` with timestamp and tunnel_id every 15 seconds
2. **Agent responds**: `PongFrame` echoing timestamp and tunnel_id
3. **Server tracks**: Updates `lastPong` timestamp
4. **Timeout**: If no pong for 5 minutes, server force-closes connection

## Custom URLs and SPA Redirection

### Custom URLs
Allow memorable, branded paths instead of UUID-based URLs:
- **Traditional**: `https://server.run.app/__pub__/abc123-def456/`
- **Custom**: `https://server.run.app/bob/chatbot/`

### SPA Redirection
Hybrid redirection system for React/Vue/Angular apps:
- **Problem**: SPAs expect to run at root path but are served under custom URLs
- **Solution**: Initial request redirected to root, subsequent requests routed directly
- **Features**: Session-based client tracking, automatic cleanup, no code changes required

### Example Usage
```bash
# SPA with redirection
cd agent && go run . \
  --server https://connect.vexorium.net \
  --local http://localhost:3000 \
  --custom-url company/dashboard \
  --use-redirect
```

## Security Features

- ChaCha20-Poly1305 AEAD encryption for all WebSocket messages
- HKDF key derivation with random salts per session
- Separate send/receive keys for bidirectional security
- Message size limits (1MB plaintext, 8MB response body)

## GitHub Actions Workflow

### Automated Deployment
- **Setup**: Requires GCP service account and GitHub secret `GCP_SERVICE_ACCOUNT_KEY`
- **Triggers**: Main branch pushes deploy to production, PRs create staging environments
- **Features**: Zero-downtime deployments, health verification, per-PR staging with automatic cleanup

### Setup Commands
```bash
# Create GCP service account with minimal permissions
./setup-gcp-service-account.sh

# Staging environments automatically created for PRs
# Production deployment on main branch merge
```

## Important Notes

- Server state is in-memory only (single instance deployment required)
- Use `--max-instances=1` for Cloud Run deployment
- Agent auto-reconnects and re-registers on credential failures
- Production server URL: https://connect.vexorium.net
- For server issues, check GCP Cloud Run logs: `server/logs.sh -l 1000`
- When modifying agentlib, maintain modular architecture - agent.go should only coordinate
- Smart routing requires no application changes - works transparently with SPAs
- TCP tunneling supports databases, SSH, and other TCP services
- Custom URLs are case-sensitive and must be unique across the server
- System endpoints use uncommon names (`__health__`, `__pub__`, etc.) to free up namespace

## Frame Type Reference

All messages between server and agent are encrypted with ChaCha20-Poly1305. Key frame types:

**Connection Management:**
- `HandshakeFrame` - Server sends salt for key derivation
- `RegisterFrame` - Agent sends registration with protocol/port
- `RegisterResponseFrame` - Server responds with tunnel credentials
- `PingFrame` / `PongFrame` - Health monitoring (15s interval, 5min timeout)

**HTTP Tunneling:**
- `ReqFrame` - Server → Agent: HTTP request to forward
- `RespFrame` - Agent → Server: HTTP response
- `ChunkedRespFrame` - Agent → Server: Chunked/streaming response

**TCP Tunneling:**
- `TcpConnectFrame` - Server → Agent: New TCP connection (includes port, no address field)
- `TcpDataFrame` - Bidirectional: Raw TCP data
- `TcpDisconnectFrame` - Either side: Close connection with reason

**WebSocket Tunneling:**
- `WebSocketFrame` - Bidirectional WebSocket frame forwarding
- Direction field: `to_server` or `to_client`

**HTTP Proxy:**
- `ProxyReqFrame` - Server → Agent: Make external HTTP request
- `ProxyRespFrame` - Agent → Server: External HTTP response

## Type Consistency Rules

When modifying frame types, ensure **exact consistency** between server and agent:

1. **Field names must match exactly**: `conn_id`, `tunnel_id`, `req_id` (not `connID`, `tunnelId`)
2. **JSON tags must match**: `json:"type"`, `json:"conn_id"`
3. **Data types must match**: `time.Time` not `int64`, `[]byte` not `string`
4. **Required vs optional**: Agent `omitempty` must match server expectations
5. **No extra fields**: Agent types should not have fields server doesn't send

**Example of incorrect agent type:**
```go
// ❌ WRONG - has extra Address field server doesn't send
type TcpConnectFrame struct {
    Type    string `json:"type"`
    ConnID  string `json:"conn_id"`
    Address string `json:"address"`  // Server never sends this!
    Port    int    `json:"port"`
}
```

**Correct agent type (matches server):**
```go
// ✅ CORRECT - exact match with server
type TcpConnectFrame struct {
    Type   string `json:"type"`
    ConnID string `json:"conn_id"`
    Port   int    `json:"port"`
}
```

## Troubleshooting

### Common Issues
- **502 on public URL**: Agent not connected or crashed - check agent logs
- **Timeout waiting agent**: Internal service slow/unreachable - verify service health
- **401 on WebSocket**: Wrong credentials - re-register agent
- **"Unknown message type: ping"**: Agent doesn't handle ping - ensure `connection.go` has `case "ping"` handler
- **Index out of range panic**: Agent using `strings.Split(url, "://")[1]` without checking - validate `://` exists first
- **Compilation errors in agentlib**: Ensure function calls use correct "New" suffixes

### TCP Tunnel Issues
- **Windows crash on bare hostname**: Fixed - agent now supports both `localhost` and `tcp://localhost:3306` formats
- **TCP connection refused**: Verify local service is running on specified port
- **TCP data not flowing**: Check `TcpDataFrame` and `TcpDisconnectFrame` handlers on both sides

### SPA Issues
- **Blank page under custom URL**: Add `--use-redirect` flag
- **Assets not loading**: Verify client session in `/__health__` endpoint
- **Redirection loops**: Ensure local app serves from root path `/`

### Debug Commands
```bash
# Check agent connection status
curl https://server/__health__ | jq '.active_connections'

# Monitor redirection sessions
curl https://server/__health__ | jq '.redirection_sessions'

# Test agent build after agentlib changes
cd agent && go build -o ../agent-bin

# Verify no vet issues
go vet ./...

# Check for race conditions
go test -race ./...
```
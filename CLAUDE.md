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
- **pkg/agentlib/**: Shared agent logic library
- **pkg/crypto/**: Encryption/decryption utilities with ChaCha20-Poly1305
- **pkg/metrics/**: Metrics collection and reporting utilities

### Key Components
- **WebSocket Protocol**: JSON messages over encrypted WebSocket (server→agent: ReqFrame, agent→server: RespFrame)
- **Key Exchange**: HKDF-based key derivation with per-session salts
- **Enhanced Smart Routing**: Multi-header client fingerprinting with learning capabilities for SPA asset routing
- **Client Tracker**: Intelligent client identification and tunnel mapping with adaptive learning
- **TCP Tunneling**: Support for raw TCP connections through WebSocket tunnels
- **Custom URLs**: Case-sensitive memorable URLs like `/bob/chatbot` instead of `/pub/{uuid}`
- **In-memory State**: Server keeps tunnels and agent connections in memory (PoC limitation)

## Development Commands

### Building
```bash
# Build server
cd server && go build -o ../server-bin

# Build agent  
cd agent && go build -o ../agent-bin

# Build reverse-proxy-agent
cd reverse-proxy-agent && go build -o ../reverse-proxy-agent-bin

# Build all modules
go work sync
```

### Running Locally
```bash
# Start server
cd server && go run main.go

# Start agent (after registering)
cd agent && go run main.go --server http://localhost:8080 --local http://127.0.0.1:3000

# Alternative: Use reverse-proxy-agent
cd reverse-proxy-agent && go run main.go --public-url <tunnel-url> --local-port 8081
```

### Testing
```bash
# Test individual modules
cd server && go test ./...
cd agent && go test ./...
cd reverse-proxy-agent && go test ./...
cd pkg/crypto && go test ./...
cd pkg/agentlib && go test ./...

# Test all modules
go work sync && go test ./...

# Test smart routing specifically
cd server && go test -v smart_routing_test.go main.go
```

### Docker & Deployment
```bash
# Build server image
cd server && docker build -f Dockerfile -t gcp-proxy-server ..

# Deploy to GCP using deploy script (recommended)
cd server && ./deploy.sh

# Other useful scripts
cd server && ./logs.sh -l 1000          # View Cloud Run logs, 1000 is log line number.
cd server && ./quick-logs.sh    # View recent logs
cd server && ./restart.sh       # Restart Cloud Run service
cd server && make build         # Build using Makefile
```

## GitHub Actions

### Setup
The repository includes automated GitHub Actions workflow for deployment to GCP Cloud Run.

#### Prerequisites
1. **GCP Service Account**: Run the setup script to create a service account with minimal permissions:
   ```bash
   ./setup-gcp-service-account.sh
   ```

2. **GitHub Secrets**: Configure the following repository secret in GitHub (Settings > Secrets and variables > Actions):
   - `GCP_SERVICE_ACCOUNT_KEY`: Base64-encoded service account key

### Workflow Jobs
1. **Test**: Run all Go module tests with caching
2. **Deploy**: Build using Cloud Build and deploy to Cloud Run (main branch pushes only)
3. **Deploy Staging**: Create per-PR staging environments (pull requests)
4. **Cleanup Staging**: Remove staging environments when PRs are closed

### Branch Strategy
- **Main branch**: Automatic deployment to production
- **Pull requests**: Deploy to isolated staging environment per PR
- **All branches**: Run full test suite

### Deployment Features
- Zero-downtime deployments via Cloud Run
- Automatic health verification (`/__health__` endpoint)
- Prometheus metrics endpoint verification
- Go module caching for faster builds
- Per-PR staging environments with automatic cleanup
- PR comments with staging URLs

## Message Flow

### HTTP Tunneling
1. **Registration**: Agent connects to `/__ws__` and registers over encrypted WebSocket → receives `{id, secret, public_url}`
2. **Key Exchange**: Server sends handshake with salt, agent ACKs
3. **Request Flow**: Public request to `/__pub__/{id}/...` → encrypted ReqFrame → agent forwards to local service → RespFrame back

### TCP Tunneling
1. **Registration**: Agent connects to `/__ws__` and registers with `{"protocol":"tcp","port":3306}` → receives `{id, secret, public_url}`
2. **WebSocket**: Agent maintains connection at `/__ws__`
3. **TCP Proxy**: Raw TCP connections forwarded through WebSocket tunnel

### Smart Routing (SPA Asset Handling)
1. **Asset Request**: Browser requests `/assets/file.js` (missing tunnel prefix)
2. **Client Fingerprinting**: Multi-header analysis to identify originating tunnel
3. **Smart Routing**: Automatic redirect to `/__pub__/{detected-id}/assets/file.js`
4. **Learning**: System learns and caches successful mappings for future requests

## Custom URLs

### Overview
Custom URLs allow memorable, branded paths instead of UUID-based URLs:
- **Traditional**: `https://server.run.app/__pub__/abc123-def456/`
- **Custom**: `https://server.run.app/bob/chatbot/`

### Registration
Request custom URLs during tunnel registration:
```json
POST /__register__
{
  "protocol": "http",
  "custom_url": "bob/chatbot"
}
```

Response includes both default and custom URLs:
```json
{
  "id": "abc123-def456",
  "secret": "...",
  "public_url": "https://server/__pub__/abc123-def456",
  "custom_url": "https://server/bob/chatbot",
  "protocol": "http"
}
```

### URL Rules (Case-Sensitive)
- **Format**: `/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*`
- **Length**: 1-64 characters (after removing slashes)
- **Case-sensitive**: `/Bob/ChatBot` ≠ `/bob/chatbot`
- **Reserved paths**: Cannot use `__health__`, `__pub__`, `__register__`, `__ws__`, `__tcp__`
- **Conflict detection**: Each custom URL must be unique

### Examples
```bash
# Register with custom URL
curl -X POST https://server/__register__ \
  -H "Content-Type: application/json" \
  -d '{"protocol": "http", "custom_url": "company/api"}'

# Access via custom URL
curl https://server/company/api/users

# Traditional URL still works
curl https://server/__pub__/abc123-def456/users
```

### Path Handling
- **Root**: `/bob/chatbot` → agent receives `/`
- **Nested**: `/bob/chatbot/api/users` → agent receives `/api/users`
- **Prefix matching**: `/bob/chatbot/v2` matches `/bob/chatbot` custom URL

## Security Features

- ChaCha20-Poly1305 AEAD encryption for all WebSocket messages
- HKDF key derivation with random salts per session
- Separate send/receive keys for bidirectional security
- Message size limits (1MB plaintext, 8MB response body)

## Important Notes

- Server state is in-memory only (single instance deployment required)
- Use `--max-instances=1` for Cloud Run deployment
- Agent auto-reconnects and re-registers on credential failures
- Streaming responses supported with timeouts
- Use server/deploy.sh to deploy server to GCP
- Always use GCP server to test client and proxy
- GCP server url is https://connect.vexorium.net
- Always write new unit test for new feature and run unit test for regression test
- Smart routing requires no application changes - works transparently with SPAs
- TCP tunneling supports databases, SSH, and other TCP services
- Health endpoint `/__health__` provides connection status and custom URL metrics
- Custom URLs are case-sensitive and must be unique across the server
- System endpoints use uncommon names (`__health__`, `__pub__`, etc.) to free up namespace
- For server issue, please check GCP cloud run log for trouble shooting. You can use tool `server/logs.sh -l 1000` to check server log.

## Client Updates Required

When using the new endpoint structure, client agents need to be updated to use the new system endpoints:

### Agent Registration
- **Old**: `POST /register`
- **New**: `POST /__register__`

### WebSocket Connection
- **Old**: `GET /ws?id=...&secret=...`
- **New**: `GET /__ws__?id=...&secret=...`

### Health Monitoring
- **Old**: `GET /health`
- **New**: `GET /__health__`

### Legacy Support
- Existing agents will fail to connect until updated to use new endpoints
- No automatic redirect from old to new endpoints for security reasons
- Update deployment scripts and agent configurations before deploying new server
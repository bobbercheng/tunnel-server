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
- **server/**: Cloud Run service (handles `/register`, `/ws`, `/pub/`)  
- **agent/**: Client binary that connects to server and forwards to local services
- **pkg/agentlib/**: Shared agent logic library
- **pkg/crypto/**: Encryption/decryption utilities with ChaCha20-Poly1305

### Key Components
- **WebSocket Protocol**: JSON messages over encrypted WebSocket (server→agent: ReqFrame, agent→server: RespFrame)
- **Key Exchange**: HKDF-based key derivation with per-session salts
- **In-memory State**: Server keeps tunnels and agent connections in memory (PoC limitation)

## Development Commands

### Building
```bash
# Build server
cd server && go build -o ../server-bin

# Build agent  
cd agent && go build -o ../agent-bin

# Build all modules
go work sync
```

### Running Locally
```bash
# Start server
cd server && go run main.go

# Start agent (after registering)
cd agent && go run main.go --server http://localhost:8080 --local http://127.0.0.1:3000
```

### Testing
```bash
# Test individual modules
cd server && go test ./...
cd agent && go test ./...
cd pkg/crypto && go test ./...

# Test all modules
go work sync && go test ./...
```

### Docker
```bash
# Build server image
cd server && docker build -f Dockerfile -t gcp-proxy-server ..

# Deploy to GCP (from server directory)
gcloud builds submit --tag gcr.io/$PROJECT_ID/tunnel-server .
```

## Message Flow

1. **Registration**: Agent POST `/register` → receives `{id, secret, public_url}`
2. **WebSocket**: Agent connects to `/ws?id=...&secret=...`
3. **Key Exchange**: Server sends handshake with salt, agent ACKs
4. **Request Flow**: Public request to `/pub/{id}/...` → encrypted ReqFrame → agent forwards to local service → RespFrame back

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
- Use @server/deploy.sh to deploy server to GCP
- Always use GCP server to test client and proxy
- GCP server url is https://tunnel-server-3w6u4kmniq-ue.a.run.app
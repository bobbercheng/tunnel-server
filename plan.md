# Tunnel Server Simplification - Rewrite Plan

## Problem Statement

The current codebase has ~7,000+ lines of server code and ~3,000+ lines of agent library code, containing enormous complexity that far exceeds what's needed for a basic HTTP tunnel service. Most of the complexity comes from features like smart routing (client fingerprinting with ~30 header fields, parallel routing, affinity management), SPA redirection, custom vanity URLs, GeoIP-based geographical routing, TCP tunneling, HTTP proxy mode, Prometheus metrics, chunked response reassembly, response queuing, and more.

**Goal**: A simple, stable tunnel service on GCP Cloud Run to tunnel an internal web service (with streaming/SSE and WebSocket support). Nothing more.

## What to REMOVE (and why)

| Feature | Lines (approx) | Why Remove |
|---------|----------------|------------|
| Smart routing / client fingerprinting | ~800 | Over-engineered; each tunnel gets its own URL |
| Custom vanity URLs (`/bob/chatbot`) | ~400 | Unnecessary; `/__pub__/{id}/` is sufficient |
| SPA redirection system | ~300 | App-level concern, not tunnel's job |
| Affinity manager | ~370 | Only needed for smart routing |
| Client tracker | ~700 | Only needed for smart routing |
| TCP tunneling | ~340 | Out of scope - HTTP only |
| HTTP proxy mode (CONNECT) | ~160 | Out of scope |
| GeoIP routing | ~200 | Over-engineered |
| Prometheus metrics | ~300 | Can add back later if needed |
| Chunked response assembly | ~70 | Replace with streaming-only approach |
| Response queuing | ~120 | Over-complicated reconnection logic |
| Periodic connection validation | ~100 | Ping/pong is sufficient |
| Agent: URL rewriting | ~400 | App-level concern |
| Agent: uTLS browser fingerprinting | ~300 | Unnecessary |
| Agent: Debug file logging | ~170 | Standard logging is enough |
| Agent: Request queue | ~100 | Unnecessary |
| `reverse-proxy-agent/` module | ~300 | Out of scope |
| `pkg/metrics/` module | ~300 | Remove with Prometheus |

## What to KEEP (simplified)

### Core Protocol (unchanged)
1. **WebSocket connection** - Agent connects to server at `/__ws__`
2. **Key exchange** - HKDF + ChaCha20-Poly1305 encryption (keep `pkg/crypto/` as-is)
3. **Registration** - Agent registers, gets `{id, secret}` and public URL
4. **Ping/pong** - Health monitoring (15s interval, 5min timeout)

### HTTP Tunneling
1. `/__pub__/{id}/path` - Forward HTTP requests to agent
2. Agent forwards to local service, returns response
3. Regular responses: single `resp` frame
4. Streaming/SSE: `streaming_start` → `streaming_chunk`* → `streaming_end`
5. WebSocket upgrade: client↔server↔agent bidirectional forwarding

### Endpoints (only 3 + catch-all)
| Endpoint | Purpose |
|----------|---------|
| `/__ws__` | Agent WebSocket connection |
| `/__pub__/{id}/...` | Public HTTP access to tunnel |
| `/__health__` | Simple health check (list active tunnels) |
| `/` (catch-all) | Return 404 |

## New Architecture

### Module Structure (simplified)
```
tunnel-server/
├── go.work              # Just ./server, ./agent, ./pkg/crypto
├── pkg/crypto/          # KEEP AS-IS (already clean)
│   └── stream.go
├── server/
│   ├── main.go          # ~40 lines: HTTP mux + server startup
│   ├── tunnel.go        # ~150 lines: tunnel state, agent conn struct, helpers
│   ├── ws.go            # ~200 lines: WebSocket handler, key exchange, registration, message loop
│   ├── pub.go           # ~180 lines: public HTTP handler (regular + streaming + WebSocket upgrade)
│   └── health.go        # ~30 lines: health endpoint
├── agent/
│   ├── main.go          # ~40 lines: flag parsing, agent startup
│   ├── agent.go         # ~200 lines: connect, register, message loop, reconnect
│   ├── http.go          # ~100 lines: forward HTTP request to local, return response
│   ├── stream.go        # ~100 lines: handle streaming responses (SSE)
│   └── websocket.go     # ~80 lines: handle WebSocket upgrade + forwarding
└── CLAUDE.md            # Updated
```

**Total estimated: ~1,100 lines** (down from ~10,000+)

### Frame Types (reduced from 15+ to 7)

```go
// Connection
HandshakeFrame    // server→agent: salt for key derivation
RegisterFrame     // agent→server: register tunnel
RegisterRespFrame // server→agent: tunnel credentials
PingFrame         // bidirectional health check
PongFrame         // bidirectional health check

// HTTP tunneling
ReqFrame          // server→agent: HTTP request
RespFrame         // agent→server: HTTP response (also used for streaming_start/chunk/end)

// WebSocket tunneling
WebSocketFrame    // bidirectional WebSocket frame forwarding
```

### Server State (minimal)
```go
var (
    agents   map[string]*agentConn   // id → WebSocket connection
    tunnels  map[string]*TunnelInfo  // id → {secret, created}
)
```

No more: `customURLs`, `clientTracker`, `affinityManager`, `globalRequestCorrelation`, `ipTunnelMappings`, `geoRouting`, `clientAssetMap`.

### Agent Simplification
- Single-file-friendly agent logic (or 4 small files)
- `--server`, `--local` flags only (drop `--custom-url`, `--use-redirect`, `--protocol`, `--port`, `--rewrite-rules-file`, `--debug-log`, `--debug-file`)
- Standard `net/http` client (drop uTLS browser fingerprinting)
- Simple reconnection: on disconnect, wait 2s, reconnect
- No URL rewriting, no request queuing, no debug file logging

## Implementation Steps

### Step 1: Create the branch and set up new server
1. Create `claude/simplify-tunnel-server-OmPCo` branch
2. Delete all existing server `.go` files
3. Write new `server/main.go` - minimal HTTP server with 3 endpoints
4. Write new `server/tunnel.go` - types, state, helper functions
5. Write new `server/ws.go` - WebSocket handler (key exchange + registration + message loop)
6. Write new `server/pub.go` - public HTTP handler (regular + streaming + WS upgrade)
7. Write new `server/health.go` - simple health endpoint
8. Update `server/go.mod` - remove Prometheus, GeoIP dependencies

### Step 2: Rewrite the agent
1. Delete all existing `pkg/agentlib/` files
2. Write new `agent/main.go` - simplified flag parsing
3. Write new `agent/agent.go` - connect, register, reconnect loop
4. Write new `agent/http.go` - forward HTTP requests to local service
5. Write new `agent/stream.go` - handle streaming (SSE) responses
6. Write new `agent/websocket.go` - handle WebSocket forwarding
7. Update `agent/go.mod` - minimal dependencies

### Step 3: Clean up workspace
1. Remove `reverse-proxy-agent/` module entirely
2. Remove `pkg/agentlib/` module entirely (agent logic now in `agent/`)
3. Remove `pkg/metrics/` module entirely
4. Update `go.work` to only include `./server`, `./agent`, `./pkg/crypto`
5. Remove test files for deleted features
6. Update `CLAUDE.md`

### Step 4: Verify
1. `go build ./...` succeeds
2. `go vet ./...` clean
3. Manual test: start server, start agent, curl through tunnel
4. Verify streaming works (SSE)
5. Verify WebSocket forwarding works

## Key Design Decisions

1. **No custom URLs** - Every tunnel is accessed at `/__pub__/{id}/`. Simple, predictable, no routing ambiguity.

2. **No TCP tunneling** - HTTP-only. Reduces protocol complexity significantly.

3. **No smart routing** - If you have the tunnel ID, you get to the tunnel. No guessing.

4. **Agent inlined** - No separate `pkg/agentlib`. The agent is simple enough to live in `agent/`.

5. **Streaming via RespFrame reuse** - Instead of separate `ChunkedRespFrame` and `HeartbeatFrame` types, reuse `RespFrame` with `Type` field set to `streaming_start`, `streaming_chunk`, or `streaming_end`.

6. **Keep encryption** - ChaCha20-Poly1305 is already clean and well-implemented in `pkg/crypto/`. No reason to change it.

7. **Keep reconnection with credentials** - Agent reconnects with `?id=X&secret=Y` on the WebSocket URL. Simple, works.

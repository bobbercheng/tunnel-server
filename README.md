# Cloud Run Reverse-Tunnel HTTP Proxy (Go)

---

## 1. Overview

This project implements a lightweight reverse-tunnel HTTP proxy using Google Cloud Run and Go.
- A Cloud Run "server" exposes a public URL: `https://<service>/__pub__/{tunnel_id}/...`
- An on-prem/inside-network "agent" keeps a persistent WebSocket to the server.
- Every public HTTP request received by the server is forwarded through that WebSocket to the agent, which proxies it to your internal HTTP service and streams the response back.

This is faster and simpler than the Firestore/Cloud Functions long-polling approach because it uses a single, long-lived WebSocket connection for bidirectional messaging.

---

## 2. Components

### 2.1 Server (Cloud Run)
- **Endpoints:**
  - `GET /__ws__` → WebSocket endpoint for agent connections and registration (supports custom URLs and SPA redirection)
  - `ANY /__pub__/{id}/...` → Public HTTP entrypoint, forwarded to the agent
  - `ANY /{custom-url}/...` → Custom URL routing with optional SPA redirection support
  - `GET /__health__` → Health check and tunnel status
- **Registration:** Now happens over encrypted WebSocket connection, not HTTP POST
- **Features:**
  - Enhanced Smart Routing with multi-header client fingerprinting
  - Custom URL support (e.g., `/bob/chatbot` instead of `/__pub__/{uuid}`)
  - **SPA Redirection Support**: Opt-in redirection for React/Vue/Angular apps with base path issues
  - ChaCha20-Poly1305 encryption for all tunnel communication
- Keeps in-memory maps for tunnels and active agents (PoC). For production, use Redis/Memorystore or Pub/Sub/NATS to share state across instances.

### 2.2 Agent (runs near your internal HTTP service)
- Connects to WebSocket at `/__ws__` and registers over encrypted connection
- Registration supports custom URLs and optional SPA redirection
- For each request frame, forwards to the local HTTP service and returns the response over the WebSocket
- **SPA Support**: Can enable redirection mode to solve React Router base path issues

### 2.3 Message protocol (JSON over WebSocket)

**Server → Agent**
```json
{
  "type": "req",
  "req_id": "...",
  "method": "...",
  "path": "...",
  "query": "...",
  "headers": { "Header": ["Value"] },
  "body": ""
}
```

**Agent → Server**
```json
{
  "type": "resp",
  "req_id": "...",
  "status": 200,
  "headers": { "Header": ["Value"] },
  "body": ""
}
```

---

## 3. Directory Layout

```
server/
├── main.go
├── go.mod
└── Dockerfile

agent/
├── main.go
└── go.mod
```

---

## 4. Prerequisites

- Go 1.22+
- gcloud CLI
- A Google Cloud project with:
  - Cloud Run API enabled
  - Cloud Build API enabled
  - Artifact Registry or Container Registry enabled (gcr.io or artifactregistry)
  - (Optional) A custom domain mapped to the Cloud Run service if you want a stable PUBLIC_BASE_URL

---

## 5. Quick Start (Minimal: Do Not Set PUBLIC_BASE_URL)

This path relies on the server code's fallback to `r.Host` when `PUBLIC_BASE_URL` is not set.

1. **Build and push the server image**
   ```bash
   export PROJECT_ID=your-project
   export REGION=us-central1
   gcloud builds submit --tag gcr.io/$PROJECT_ID/tunnel-server ./server
   ```

2. **Deploy to Cloud Run**
   ```bash
   gcloud run deploy tunnel-server \
     --image gcr.io/$PROJECT_ID/tunnel-server \
     --platform managed \
     --region $REGION \
     --allow-unauthenticated \
     --max-instances 1
   ```
   > **Note:** `--max-instances=1` is recommended for this PoC, since state is in-memory.

3. **Capture the service URL** (shown after deploy). Example:
   ```
   https://tunnel-server-abc123-uc.a.run.app
   ```

4. **Run the agent** next to your internal HTTP service
   ```bash
   cd agent
   go run . \
     --server https://tunnel-server-abc123-uc.a.run.app \
     --local  http://127.0.0.1:8080
   ```
   The agent will:
   - Connect to WebSocket at `/__ws__` and register over encrypted connection
   - Print `public_url` (e.g. `https://tunnel-server-abc123-uc.a.run.app/__pub__/<id>`)
   - Maintain persistent encrypted tunnel

5. **Test**
   ```bash
   curl -i https://tunnel-server-abc123-uc.a.run.app/__pub__/<id>/
   ```
   You should see the same response as your local service at `http://127.0.0.1:8080/`

---

## 6. Optional: Set PUBLIC_BASE_URL

You can set `PUBLIC_BASE_URL` to the Cloud Run URL (or a custom domain) so the server returns a stable `public_url` during registration.

**Two-step approach:**

1. **Deploy without env var, capture the URL:**
   ```bash
   URL=$(gcloud run deploy tunnel-server \
     --image gcr.io/$PROJECT_ID/tunnel-server \
     --platform managed \
     --region $REGION \
     --allow-unauthenticated \
     --max-instances 1 \
     --format='value(status.url)')
   ```

2. **Update the service:**
   ```bash
   gcloud run services update tunnel-server \
     --platform managed \
     --region $REGION \
     --set-env-vars PUBLIC_BASE_URL=$URL
   ```

If you already have a custom domain bound (e.g. `https://tunnel.yourdomain.com`), set that directly at deploy time.

---

## 7. Running the Agent as a Service (systemd Example)

Example systemd unit (linux):

```ini
[Unit]
Description=Cloud Run Reverse Tunnel Agent
After=network-online.target

[Service]
User=youruser
ExecStart=/usr/local/bin/agent \
  --server https://tunnel-server-abc123-uc.a.run.app \
  --local  http://127.0.0.1:8080 \
  --custom-url myapp \
  --use-redirect
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

---

## 8. SPA Redirection Support (React/Vue/Angular)

### 8.1 Problem Solved

Single Page Applications (SPAs) often fail when served under custom URLs because they expect to run at the root path (`/`) but are actually served under a custom path like `/myapp`. This causes:

- React Router failing to match routes
- Blank pages instead of the expected application
- Asset loading issues

### 8.2 Solution: Hybrid Redirection

The server provides an opt-in **hybrid redirection solution** that:

1. **Redirects initial requests** from custom URL to root (`/myapp` → `/`) 
2. **Tracks client sessions** using sophisticated fingerprinting
3. **Routes subsequent requests** directly to the correct tunnel without redirection
4. **Preserves content** (no HTML modification required)

### 8.3 Agent Usage

#### Enable SPA redirection with agent command line:
```bash
# React/Vue/Angular app with SPA redirection
cd agent
go run . \
  --server https://tunnel-server-abc123-uc.a.run.app \
  --local http://localhost:3000 \
  --custom-url myapp \
  --use-redirect
```

#### Agent flags for SPA support:
- `--custom-url`: Custom URL path (required for redirection)
- `--use-redirect`: Enable SPA redirection mode (optional, requires custom URL)

#### Example registration output:
```
Connection established successfully with encryption.
No tunnel id/secret provided, registering new tunnel...
Registered successfully!
  ID: abc123-def456-789abc-012def
  Secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  Public URL: https://tunnel-server-abc123-uc.a.run.app/__pub__/abc123-def456-789abc-012def
  Custom URL: https://tunnel-server-abc123-uc.a.run.app/myapp
  SPA Redirection: Enabled
```

**Note:** Agent registration happens exclusively via encrypted WebSocket connection.

### 8.4 Real-World Examples

#### React App (Create React App / Vite):
```bash
# Local React dev server
npm start  # runs on http://localhost:3000

# Agent with SPA redirection
./agent-bin \
  --server https://tunnel-server-abc123-uc.a.run.app \
  --local http://localhost:3000 \
  --custom-url company/dashboard \
  --use-redirect

# Access via: https://tunnel-server-abc123-uc.a.run.app/company/dashboard
# React Router works normally - no code changes needed!
```

#### Vue.js App:
```bash
# Local Vue dev server
npm run serve  # runs on http://localhost:8080

# Agent for Vue SPA
./agent-bin \
  --server https://tunnel-server-abc123-uc.a.run.app \
  --local http://localhost:8080 \
  --custom-url client/app \
  --use-redirect
```

#### Angular App:
```bash
# Local Angular dev server
ng serve  # runs on http://localhost:4200

# Agent for Angular SPA
./agent-bin \
  --server https://tunnel-server-abc123-uc.a.run.app \
  --local http://localhost:4200 \
  --custom-url demo/angular \
  --use-redirect
```

### 8.5 How It Works

1. **First request** to `/myapp` → Server returns `307 Temporary Redirect` to `/`
2. **Client session created** mapping the client to the tunnel 
3. **Subsequent requests** (`/`, `/api/data`, `/assets/app.js`) route directly to tunnel
4. **React app runs normally** as it thinks it's at root path

### 8.6 Benefits

- ✅ **No code changes** required in your SPA
- ✅ **Works with all frameworks** (React, Vue, Angular, etc.)
- ✅ **Preserves performance** (only first request redirected)
- ✅ **Session-based** (different users get separate sessions)
- ✅ **Automatic cleanup** (30-minute TTL)

### 8.7 Agent Command Reference

#### Full agent help:
```bash
./agent-bin --help
```

#### Common agent configurations:
```bash
# Basic tunnel (no custom URL)
./agent-bin --server https://server.run.app --local http://localhost:8080

# Custom URL (no redirection)
./agent-bin --server https://server.run.app --local http://localhost:8080 --custom-url myapi

# SPA with redirection (requires custom URL)
./agent-bin --server https://server.run.app --local http://localhost:3000 --custom-url myapp --use-redirect

# TCP tunnel (for databases, SSH, etc.)
./agent-bin --server https://server.run.app --local tcp://localhost:3306 --protocol tcp --port 3306
```

#### Validation and errors:
```bash
# Error: redirection requires custom URL
./agent-bin --server https://server.run.app --local http://localhost:3000 --use-redirect
# Output: --use-redirect requires a --custom-url

# Error: TCP requires port
./agent-bin --server https://server.run.app --local tcp://localhost:3306 --protocol tcp
# Output: --port is required for TCP tunnels
```

### 8.8 Monitoring

Check redirection status via health endpoint:
```bash
curl https://your-server/__health__ | jq '.redirection_sessions'
```

```json
{
  "active_sessions": 1,
  "total_sessions": 5, 
  "total_requests": 127,
  "sessions_by_tunnel": {"abc123": 1},
  "sessions_by_custom_url": {"myapp": 1}
}
```

#### Health endpoint shows agent redirection status:
```bash
curl https://your-server/__health__ | jq '.active_connections'
```

```json
[
  {
    "id": "abc123-def456",
    "connected_at": "2024-01-01T00:00:00Z",
    "encrypted": true,
    "custom_url": "myapp",
    "use_redirect": true
  }
]
```

---

## 9. Security Notes

- Protect `/register` (IAM, mTLS, an API key, or a signed token).
- Consider signing every frame (HMAC) to prevent tampering.
- Rotate secrets and expire tunnels after inactivity.
- Optionally whitelist IPs or require JWTs on `/__pub__` or on `/__ws__`.

---

## 9. Scaling Beyond One Instance

- Replace all in-memory state (tunnels, agent connections, pending waiters) with:
  - Redis/Memorystore to store tunnel metadata and map `tunnel_id` → instance holding the WebSocket
  - A message broker (Pub/Sub, NATS, Redis streams, Kafka) to route req/resp frames across instances
- Add sticky routing or a lookup service to find which instance holds a particular agent connection, then forward frames accordingly.
- Remove `--max-instances=1` once state is externalized.

---

## 10. Streaming and Large Bodies

- The PoC sends entire request/response bodies as JSON (base64). For large bodies or streaming:
  - Switch to binary frames
  - Implement chunked frames (`req-chunk`, `resp-chunk`)
  - Or upgrade to HTTP/2 (gRPC) or use raw TCP/WebSocket binary streams without JSON

---

## 11. Observability

- Log a unique `req_id` for every proxied request
- Add metrics (request count, latency, error rate)
- Add tracing (OpenTelemetry) to tie public requests to internal forwarding

---

## 12. Common Troubleshooting

| Symptom | Cause | Solution |
|---------|--------|----------|
| `curl` to `/__pub__/` returns 502 or "agent not connected" | Agent not connected or crashed | Check agent logs |
| "timeout waiting agent" | Internal HTTP service slow or not reachable | Increase timeouts or verify service |
| 401 unauthorized on `/__ws__` | Wrong id/secret pair | Delete the tunnel, register again |
| Multiple agents for the same id bouncing | PoC doesn't coordinate multi-connect properly | Avoid multiple agents for the same id or implement locking with Redis |

### SPA Redirection Troubleshooting

| Symptom | Cause | Solution |
|---------|--------|----------|
| Agent error: "--use-redirect requires a --custom-url" | Using `--use-redirect` without `--custom-url` | Add `--custom-url yourapp` flag |
| SPA shows blank page under custom URL | Redirection not enabled | Add `--use-redirect` flag to agent |
| Assets (JS/CSS) not loading | SPA redirection not triggered | Check client session in `/__health__` endpoint |
| 404 on custom URL | Custom URL not registered | Verify agent connected with custom URL |
| Redirection loops | Local app redirecting internally | Ensure local app serves from root path `/` |

#### Debug SPA redirection:
```bash
# Check if agent has redirection enabled
curl https://your-server/__health__ | jq '.active_connections[] | select(.use_redirect == true)'

# Monitor redirection sessions
curl https://your-server/__health__ | jq '.redirection_sessions'

# Test redirection flow manually
curl -I https://your-server/myapp  # Should return 307 redirect
curl -I https://your-server/       # Should return 200 from your app
```

---

## 13. Cleanup

- **Delete the Cloud Run service:**
  ```bash
  gcloud run services delete tunnel-server --platform managed --region $REGION
  ```
- **Delete the image:**
  ```bash
  gcloud artifacts docker images delete gcr.io/$PROJECT_ID/tunnel-server:latest
  ```
  (or use Container Registry equivalent)

---

## 14. License

Add your preferred license (MIT/Apache-2.0/etc.) if you plan to open-source.

---

## 15. Next Steps

- Replace in-memory maps with Redis or Pub/Sub to scale horizontally
- Add authentication and authorization layers
- Support streaming/chunked messages
- Add health checks and graceful shutdown logic
- Package the agent as a static binary and provide Docker images for both sides
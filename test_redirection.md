# Hybrid Redirection Solution - Testing Guide

## Feature Overview

The hybrid redirection solution allows agents to opt-in to SPA (Single Page Application) routing support during tunnel registration. When enabled:

1. **Agent Registration**: Include `"use_redirect": true` in registration request
2. **Server Behavior**: 
   - Initial request to custom URL root (e.g., `/anythingllm`) triggers a 307 redirect to `/`
   - Server creates a redirection session mapping the client to the tunnel
   - Subsequent requests from the same client are automatically routed to the correct tunnel
3. **Client Tracking**: Uses existing sophisticated fingerprinting to maintain sessions

## Testing Steps

### 1. Start Server
```bash
cd server && go run main.go
# or use built binary
./server-bin
```

### 2. Register Agent with Redirection Enabled

#### HTTP Registration:
```bash
curl -X POST http://localhost:8080/__register__ \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "http",
    "custom_url": "anythingllm",
    "use_redirect": true
  }'
```

#### WebSocket Registration (if using agent):
Include `"use_redirect": true` in the RegisterFrame.

### 3. Test Redirection Flow

#### Initial Request (should redirect):
```bash
curl -v http://localhost:8080/anythingllm
```
Expected: 307 Temporary Redirect to `/`

#### Follow-up Requests (should route directly):
```bash
curl -v http://localhost:8080/anythingllm/api/status
curl -v http://localhost:8080/index.js
curl -v http://localhost:8080/index.css
```
Expected: Direct routing to tunnel without redirect

### 4. Monitor Health Endpoint

```bash
curl http://localhost:8080/__health__ | jq '.redirection_sessions'
```

Expected output:
```json
{
  "active_sessions": 1,
  "total_sessions": 1,
  "total_requests": 4,
  "sessions_by_tunnel": {
    "abc123-def456": 1
  },
  "sessions_by_custom_url": {
    "anythingllm": 1
  }
}
```

### 5. Verify Agent Info

```bash
curl http://localhost:8080/__health__ | jq '.active_connections[0]'
```

Should show:
```json
{
  "id": "abc123-def456",
  "custom_url": "anythingllm",
  "use_redirect": true,
  ...
}
```

## Expected Results

1. **First access** to `/anythingllm` → 307 redirect to `/`
2. **Subsequent requests** route directly to tunnel without redirect
3. **Asset requests** (`/index.js`, `/index.css`) route correctly
4. **Health endpoint** shows redirection session statistics
5. **SPA routing works** as the app thinks it's running at root path

## Troubleshooting

- Check server logs for redirection session creation/updates
- Verify `use_redirect: true` in agent registration
- Ensure client fingerprinting is consistent (same IP, User-Agent, etc.)
- Session TTL is 30 minutes - test within that window
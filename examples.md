# TCP and HTTP Tunneling Examples

## HTTP Tunneling (Existing Functionality)

### 1. Start the agent with HTTP protocol (default)
```bash
./agent-bin --server https://tunnel-server-3w6u4kmniq-ue.a.run.app --local http://127.0.0.1:8080
```

### 2. Use reverse proxy for HTTP
```bash
./reverse-proxy-agent-bin --public-url "https://tunnel-server-3w6u4kmniq-ue.a.run.app/pub/12345" --local-port 8081
```

## TCP Tunneling (New Functionality)

### 1. Start the agent with TCP protocol
```bash
# Tunnel local SSH service (port 22)
./agent-bin --server https://tunnel-server-3w6u4kmniq-ue.a.run.app --protocol tcp --port 22 --local tcp://127.0.0.1:22

# Tunnel local database service (port 5432)
./agent-bin --server https://tunnel-server-3w6u4kmniq-ue.a.run.app --protocol tcp --port 5432 --local tcp://127.0.0.1:5432
```

### 2. Use reverse proxy for TCP
```bash
# SSH tunnel - connects to /tcp/ endpoint automatically
./reverse-proxy-agent-bin --public-url "https://tunnel-server-3w6u4kmniq-ue.a.run.app/tcp/67890" --local-port 2222

# Database tunnel
./reverse-proxy-agent-bin --public-url "https://tunnel-server-3w6u4kmniq-ue.a.run.app/tcp/67890" --local-port 5433
```

### 3. Connect through TCP tunnel
```bash
# SSH through tunnel
ssh user@localhost -p 2222

# Database connection through tunnel
psql -h localhost -p 5433 -U username dbname
```

## Registration API Examples

### HTTP Registration (backward compatible)
```bash
curl -X POST https://tunnel-server-3w6u4kmniq-ue.a.run.app/register
# Returns: {"id":"12345","secret":"abc...","public_url":"https://.../pub/12345","protocol":"http"}
```

### TCP Registration
```bash
curl -X POST https://tunnel-server-3w6u4kmniq-ue.a.run.app/register \
  -H "Content-Type: application/json" \
  -d '{"protocol":"tcp","port":22}'
# Returns: {"id":"67890","secret":"def...","public_url":"https://.../tcp/67890","protocol":"tcp","tcp_port":22}
```

## Architecture Overview

### HTTP Flow
```
Client → reverse-proxy-agent:8081 → server:443/pub/12345 → agent → local-service:8080
```

### TCP Flow  
```
TCP Client → reverse-proxy-agent:2222 → server:443/tcp/67890 (WebSocket) → agent → local-service:22
```

## Message Types

### HTTP Messages (unchanged)
- `ReqFrame` - HTTP request from server to agent
- `RespFrame` - HTTP response from agent to server

### TCP Messages (new)
- `TcpConnectFrame` - Establish TCP connection
- `TcpDataFrame` - Raw TCP data transfer
- `TcpDisconnectFrame` - Close TCP connection

## Backward Compatibility

- Existing HTTP tunnels continue to work unchanged
- Default protocol is "http" if not specified
- Registration API accepts both old format (no body) and new format (with protocol/port)
- Reverse proxy agent automatically detects HTTP vs TCP based on URL pattern (/pub/ vs /tcp/)
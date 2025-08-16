# Cloud Run Log Viewer Utilities

This directory contains powerful utilities for viewing and monitoring logs from your Cloud Run tunnel server deployment.

## 🚀 Quick Start

```bash
# Show recent logs
./quick-logs.sh recent

# Show errors
./quick-logs.sh errors

# Follow logs in real-time
./quick-logs.sh live

# Show connection issues
./quick-logs.sh disconnect
```

## 📋 Available Scripts

### `quick-logs.sh` - Simple Commands
Quick shortcuts for common log viewing patterns:

| Command | Description | Example |
|---------|-------------|---------|
| `recent` or `r` | Last 5 minutes of logs | `./quick-logs.sh recent` |
| `errors` or `e` | ERROR and WARNING logs | `./quick-logs.sh errors` |
| `live` or `f` | Follow logs in real-time | `./quick-logs.sh live` |
| `ping` or `p` | Ping/pong related logs | `./quick-logs.sh ping` |
| `websocket` or `w` | WebSocket connection logs | `./quick-logs.sh websocket` |
| `disconnect` or `d` | Connection issues | `./quick-logs.sh disconnect` |
| `agent <id>` | Logs for specific agent | `./quick-logs.sh agent abc123` |
| `all` or `a` | All logs (last 2 hours) | `./quick-logs.sh all` |

### `logs.sh` - Advanced Options
Full-featured log viewer with extensive filtering:

```bash
# Basic usage
./logs.sh                              # Last 50 logs from past hour
./logs.sh -l 100                       # Show 100 log entries
./logs.sh -t 24h                       # Show logs from last 24 hours

# Filtering
./logs.sh --errors                     # Only errors and warnings
./logs.sh -s ERROR                     # Only ERROR severity
./logs.sh --ping                       # Only ping/pong logs
./logs.sh --websocket                  # Only WebSocket logs
./logs.sh --agent d73d6a94-05dc        # Logs for specific agent

# Real-time monitoring
./logs.sh -f                           # Follow logs (like tail -f)
./logs.sh --websocket -f               # Follow WebSocket logs

# Time ranges
./logs.sh --fresh                      # Last 5 minutes
./logs.sh -t 30m                       # Last 30 minutes
./logs.sh -t 1d                        # Last 24 hours
./logs.sh --all                        # All available logs

# Output formats
./logs.sh --format json               # JSON output
./logs.sh --format table              # Table format
./logs.sh --format pretty             # Colored pretty format (default)
```

## 🔍 Troubleshooting Common Issues

### Connection Problems
```bash
# Check recent connection issues
./quick-logs.sh disconnect

# Follow WebSocket connections in real-time
./logs.sh --websocket -f

# Look for specific error patterns
./logs.sh --errors -t 1h
```

### Ping/Pong Issues
```bash
# Check ping-pong communication
./quick-logs.sh ping

# Monitor ping timeouts
./logs.sh --ping -f

# Look for "Unknown message type" errors
./logs.sh -s ERROR | grep -i "unknown message"
```

### Agent-Specific Issues
```bash
# Monitor specific agent (replace with actual agent ID)
./quick-logs.sh agent d73d6a94-05dc-4e7c-abe4-75f9a6a803f1

# Follow specific agent's activity
./logs.sh --agent d73d6a94-05dc -f
```

### Performance Issues
```bash
# Check for timeouts
./logs.sh | grep -i timeout

# Look for WebSocket read limit errors
./logs.sh | grep -i "read limited"

# Monitor smart routing failures
./logs.sh | grep -i "smart routing.*failed"
```

## 🎨 Log Output Features

### Color Coding
The pretty format (default) uses colors to highlight different types of logs:
- 🔴 **Red**: Errors and failures
- 🟡 **Yellow**: Warnings and disconnections
- 🟢 **Green**: Successful connections and registrations
- 🟣 **Purple**: Ping/pong messages
- 🔵 **Blue**: WebSocket and agent messages
- 🔵 **Cyan**: Timestamps

### Log Categories
The utilities automatically detect and categorize logs:
- **Connection Events**: Agent connections, disconnections, registrations
- **Ping/Pong**: Health monitoring and timeout detection
- **WebSocket**: Protocol-level communication
- **Smart Routing**: Request routing and fallback logic
- **Errors**: Failed operations and error conditions

## 🛠️ Configuration

The scripts are pre-configured for your Cloud Run deployment:
- **Project**: `contact-center-insights-poc`
- **Service**: `tunnel-server`
- **Region**: `us-east1`

To modify these settings, edit the variables at the top of `logs.sh`:
```bash
export PROJECT_ID=your-project-id
export REGION=your-region
export SERVICE=your-service-name
```

## 📊 Common Log Patterns

### Successful Connection
```
2025-08-16 15:20:09 Agent d73d6a94-05dc-4e7c-abe4-75f9a6a803f1 reconnected with encrypted tunnel (protocol: http)
```

### Connection Timeout
```
2025-08-16 15:20:09 Agent d73d6a94-05dc appears to be unresponsive (no pong in 2m30s), forcing connection close
```

### WebSocket Read Limit Error (Fixed)
```
2025-08-16 15:20:09 WebSocket read error for agent d73d6a94: failed to read: read limited at 32769 bytes
```

### URL Mismatch Issue
```
2025-08-16 15:20:09 GET 401 https://tunnel-server-3w6u4kmniq-ue.a.run.app/__ws__?id=...
```

### Smart Routing Timeout
```
2025-08-16 15:20:09 Smart routing: TIMEOUT waiting for response from tunnel d73d6a94 (timeout: 15s)
```

## 💡 Pro Tips

1. **Real-time Monitoring**: Use `./quick-logs.sh live` for continuous monitoring during debugging
2. **Error Hunting**: Use `./quick-logs.sh errors` to quickly spot issues
3. **Agent Debugging**: Use `./quick-logs.sh agent <id>` when troubleshooting specific connections
4. **Performance Monitoring**: Use `./logs.sh -t 1h | grep -i timeout` to find timeout patterns
5. **Log Analysis**: Pipe output to `grep`, `awk`, or other tools for advanced filtering

## 🔧 Prerequisites

- `gcloud` CLI installed and authenticated
- Access to the `contact-center-insights-poc` project
- Cloud Run service `tunnel-server` deployed in `us-east1`

## 🆘 Need Help?

```bash
# Show help for quick commands
./quick-logs.sh help

# Show help for advanced options  
./logs.sh --help
```

For more information about the tunnel server itself, see the main [README.md](./README.md).

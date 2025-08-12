module example.com/tunnel/agent

go 1.23.0

toolchain go1.24.1

require tunnel.local/agentlib v0.0.0

require nhooyr.io/websocket v1.8.10 // indirect

replace tunnel.local/agentlib => ../pkg/agentlib

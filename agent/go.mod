module example.com/tunnel/agent

go 1.22

require tunnel.local/agentlib v0.0.0

require nhooyr.io/websocket v1.8.10 // indirect

replace tunnel.local/agentlib => ../pkg/agentlib

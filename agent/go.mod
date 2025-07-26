module example.com/tunnel/agent

go 1.22

require (
	gcp-proxy/pkg/agentlib v0.0.0
	nhooyr.io/websocket v1.8.10
)

replace gcp-proxy/pkg/agentlib => ../pkg/agentlib

module tunnel.local/agentlib

go 1.22

require (
	nhooyr.io/websocket v1.8.10
	golang.org/x/crypto v0.40.0
	tunnel.local/crypto v0.0.0-00010101000000-000000000000
)

require golang.org/x/sys v0.34.0 // indirect

replace tunnel.local/crypto => ../crypto

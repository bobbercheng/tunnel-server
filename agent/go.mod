module example.com/tunnel/agent

go 1.24

toolchain go1.24.1

require tunnel.local/agentlib v0.0.0

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/refraction-networking/utls v1.8.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	nhooyr.io/websocket v1.8.10 // indirect
)

replace tunnel.local/agentlib => ../pkg/agentlib

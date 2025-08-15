module example.com/tunnel/server

go 1.23.0

toolchain go1.24.1

require (
	github.com/google/uuid v1.6.0
	github.com/oschwald/geoip2-golang v1.13.0
	nhooyr.io/websocket v1.8.10
	tunnel.local/crypto v0.0.0-00010101000000-000000000000
)

require (
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
)

replace tunnel.local/crypto => ../pkg/crypto

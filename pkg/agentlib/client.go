package agentlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Browser client specifications for realistic TLS fingerprinting
var browserSpecsNew = []utls.ClientHelloID{
	utls.HelloChrome_Auto,    // Latest Chrome
	utls.HelloFirefox_120,    // Firefox 120
	utls.HelloSafari_16_0,    // Safari 16.0
	utls.HelloEdge_106,       // Edge 106
}

// uTLSRoundTripperNew implements http.RoundTripper with proper HTTP/2 protocol handling
type uTLSRoundTripperNew struct {
	spec        utls.ClientHelloID
	h2Transport *http2.Transport
	h1Transport *http.Transport
}

// newUTLSRoundTripperNew creates a new uTLS round tripper with the specified browser fingerprint
func newUTLSRoundTripperNew(spec utls.ClientHelloID) *uTLSRoundTripperNew {
	return &uTLSRoundTripperNew{
		spec: spec,
		h2Transport: &http2.Transport{
			AllowHTTP: false,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialUTLSNew(network, addr, cfg, spec)
			},
		},
		h1Transport: &http.Transport{
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialTLS: func(network, addr string) (net.Conn, error) {
				return dialUTLSNew(network, addr, nil, spec)
			},
		},
	}
}

// dialUTLSNew creates a uTLS connection with the specified browser fingerprint
func dialUTLSNew(network, addr string, cfg *tls.Config, spec utls.ClientHelloID) (net.Conn, error) {
	// Establish TCP connection
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tcpConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}

	// Extract hostname for SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // Fallback if port is missing
	}

	// Configure uTLS
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}

	// Copy additional config if provided
	if cfg != nil {
		config.NextProtos = cfg.NextProtos
		config.ServerName = cfg.ServerName
	}

	// Create uTLS connection with browser fingerprint
	uConn := utls.UClient(tcpConn, config, spec)

	// Perform TLS handshake
	if err := uConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	// Log connection details
	connState := uConn.ConnectionState()
	log.Printf("uTLS: Connection established | Host: %s | Protocol: %s | TLS: %x | Spec: %s",
		host, connState.NegotiatedProtocol, connState.Version, spec.Str())

	return uConn, nil
}

// RoundTrip implements the RoundTripper interface with protocol detection
func (u *uTLSRoundTripperNew) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("uTLS: RoundTrip called for %s | Spec: %s", req.URL.String(), u.spec.Str())

	// For HTTP/2, try h2 transport first since it can negotiate protocol
	if req.URL.Scheme == "https" {
		resp, err := u.h2Transport.RoundTrip(req)
		if err != nil {
			// If H2 fails, fall back to H1
			log.Printf("uTLS: HTTP/2 failed, falling back to HTTP/1.1: %v", err)
			return u.h1Transport.RoundTrip(req)
		}
		return resp, nil
	}

	// For HTTP, use h1 transport
	return u.h1Transport.RoundTrip(req)
}

// createUTLSTransportNew creates a HTTP transport with uTLS for browser-like TLS handshakes
func createUTLSTransportNew(isLocalhost bool) *http.Transport {
	if isLocalhost {
		// Use standard transport for localhost
		return &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return dialer.DialContext(ctx, "tcp4", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	// Use enhanced uTLS transport for external requests
	spec := browserSpecsNew[rand.Intn(len(browserSpecsNew))]
	log.Printf("uTLS: Selected browser fingerprint: %s", spec.Str())

	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Parse target for uTLS configuration
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				log.Printf("uTLS: Failed to parse address %s: %v", addr, err)
				// Fallback to standard dialer
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Establish TCP connection with context
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			tcpConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
			if err != nil {
				log.Printf("uTLS: TCP connection failed for %s:%s: %v", host, port, err)
				return nil, fmt.Errorf("TCP dial failed: %w", err)
			}

			// Configure uTLS with proper SNI and ALPN
			config := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: false,
				NextProtos:         []string{"h2", "http/1.1"}, // Support both HTTP/2 and HTTP/1.1
			}

			// Create uTLS connection with browser fingerprint
			uConn := utls.UClient(tcpConn, config, spec)

			// Perform TLS handshake with context awareness
			handshakeDone := make(chan error, 1)
			go func() {
				handshakeDone <- uConn.Handshake()
			}()

			select {
			case <-ctx.Done():
				tcpConn.Close()
				return nil, ctx.Err()
			case err := <-handshakeDone:
				if err != nil {
					tcpConn.Close()
					log.Printf("uTLS: Handshake failed for %s:%s with %s: %v", host, port, spec.Str(), err)
					return nil, fmt.Errorf("uTLS handshake failed: %w", err)
				}

				log.Printf("uTLS: Established connection using %s fingerprint | Host: %s:%s",
					spec.Str(), host, port)
				return uConn, nil
			}
		},
	}

	return transport
}

// createBrowserClientNew creates an HTTP client with uTLS and browser-like characteristics
func createBrowserClientNew(isLocalhost bool) *http.Client {
	// Create cookie jar for session persistence
	jar, _ := cookiejar.New(&cookiejar.Options{})

	var transport http.RoundTripper
	if isLocalhost {
		// Use standard transport for localhost
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return dialer.DialContext(ctx, "tcp4", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		// Use uTLS round tripper for external requests with proper HTTP/2 support
		spec := browserSpecsNew[rand.Intn(len(browserSpecsNew))]
		transport = newUTLSRoundTripperNew(spec)
	}

	return &http.Client{
		Timeout:   120 * time.Second,
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects (browser-like)
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// createStreamingBrowserClientNew creates an HTTP client for streaming with no timeout
func createStreamingBrowserClientNew(isLocalhost bool) *http.Client {
	// Create cookie jar for session persistence
	jar, _ := cookiejar.New(&cookiejar.Options{})

	var transport http.RoundTripper
	if isLocalhost {
		// Use standard transport for localhost
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				if strings.Contains(addr, "127.0.0.1:") || strings.Contains(addr, "localhost:") {
					return dialer.DialContext(ctx, "tcp4", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	} else {
		// Use uTLS round tripper for external requests with proper HTTP/2 support
		spec := browserSpecsNew[rand.Intn(len(browserSpecsNew))]
		transport = newUTLSRoundTripperNew(spec)
	}

	return &http.Client{
		Timeout:   0, // No timeout for streaming responses
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 10 redirects (browser-like)
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

func main() {
	publicURL := flag.String("public-url", "", "The public URL of the tunnel to connect to")
	localPort := flag.String("local-port", "8081", "The local port to listen on")
	flag.Parse()

	if *publicURL == "" {
		fmt.Println("The --public-url flag is required.")
		os.Exit(1)
	}

	targetURL, err := url.Parse(*publicURL)
	if err != nil {
		log.Fatalf("Invalid public URL: %v", err)
	}

	// Extract the base URL and tunnel path
	baseURL := &url.URL{
		Scheme: targetURL.Scheme,
		Host:   targetURL.Host,
	}
	tunnelPath := targetURL.Path // This should be /pub/{id}

	proxy := httputil.NewSingleHostReverseProxy(baseURL)

	// Modify the director to preserve the tunnel path
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = baseURL.Scheme
		req.URL.Host = baseURL.Host
		// Prepend the tunnel path to the request path
		req.URL.Path = strings.TrimSuffix(tunnelPath, "/") + req.URL.Path
		req.Host = baseURL.Host

		log.Printf("Forwarding %s %s to %s%s", req.Method, req.URL.Path, baseURL, req.URL.Path)
	}

	// Handle errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, fmt.Sprintf("Proxy error: %v", err), http.StatusBadGateway)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	listenAddr := ":" + *localPort
	log.Printf("Starting reverse proxy server on %s", listenAddr)
	log.Printf("Forwarding requests to %s", *publicURL)
	log.Printf("Make sure the agent for this tunnel is connected to the server!")

	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

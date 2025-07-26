package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Forwarding request for %s to %s", r.URL.Path, targetURL)
		proxy.ServeHTTP(w, r)
	})

	listenAddr := ":" + *localPort
	log.Printf("Starting reverse proxy server on %s, forwarding to %s", listenAddr, targetURL)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

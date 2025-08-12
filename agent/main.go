package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"tunnel.local/agentlib"
)

func main() {
	server := flag.String("server", "", "Cloud Run base, e.g. https://<service>-<hash>-uc.a.run.app")
	publicURL := flag.String("public-url", "", "Public URL of the tunnel, e.g. https://<service>/pub/<id>")
	local := flag.String("local", "http://127.0.0.1:8080", "local http service")
	id := flag.String("id", "", "tunnel id (optional)")
	secret := flag.String("secret", "", "tunnel secret (optional)")
	protocol := flag.String("protocol", "http", "protocol type: 'http' or 'tcp'")
	port := flag.Int("port", 0, "port number (required for TCP tunnels)")
	flag.Parse()

	// Validate TCP configuration
	if *protocol == "tcp" && *port <= 0 {
		fmt.Println("--port is required for TCP tunnels")
		os.Exit(1)
	}

	var serverURL, tunnelID, tunnelSecret string

	if *publicURL != "" {
		if *secret == "" {
			fmt.Println("--secret is required when using --public-url")
			os.Exit(1)
		}
		u, err := url.Parse(*publicURL)
		if err != nil {
			fmt.Println("Invalid --public-url:", err)
			os.Exit(1)
		}
		serverURL = u.Scheme + "://" + u.Host
		pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(pathParts) < 2 || pathParts[0] != "pub" {
			fmt.Println("Invalid public URL format. Expected /pub/<id>")
			os.Exit(1)
		}
		tunnelID = pathParts[1]
		tunnelSecret = *secret
	} else {
		if *server == "" {
			fmt.Println("--server is required if --public-url is not provided")
			os.Exit(1)
		}
		serverURL = *server
		tunnelID = *id
		tunnelSecret = *secret
	}

	agent := &agentlib.Agent{
		ServerURL: serverURL,
		LocalURL:  *local,
		ID:        tunnelID,
		Secret:    tunnelSecret,
		Protocol:  *protocol,
		Port:      *port,
	}

	agent.Run()
}

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"tunnel.local/agentlib"
)

func main() {
	server := flag.String("server", "https://connect.vexorium.net", "Cloud Run base (default: https://connect.vexorium.net)")
	publicURL := flag.String("public-url", "", "Public URL of the tunnel, e.g. https://<service>/__pub__/<id>")
	local := flag.String("local", "http://127.0.0.1:8080", "local http service")
	id := flag.String("id", "", "tunnel id (optional)")
	secret := flag.String("secret", "", "tunnel secret (optional)")
	protocol := flag.String("protocol", "http", "protocol type: 'http' or 'tcp'")
	port := flag.Int("port", 0, "port number (required for TCP tunnels)")
	customURL := flag.String("custom-url", "", "custom URL path, e.g. 'bob/chatbot'")
	useRedirect := flag.Bool("use-redirect", false, "enable SPA redirection for React/Vue/Angular apps (requires custom URL)")
	rewriteRulesFile := flag.String("rewrite-rules-file", "", "path to JSON file containing custom rewrite rules (optional)")
	debugLog := flag.Bool("debug-log", false, "enable debug logging of all requests and responses to file")
	debugFile := flag.String("debug-file", "", "path to debug log file (defaults to debug_<tunnel_id>.log)")
	flag.Parse()

	// Validate TCP configuration
	if *protocol == "tcp" && *port <= 0 {
		fmt.Println("--port is required for TCP tunnels")
		os.Exit(1)
	}

	// Validate redirection configuration
	if *useRedirect && *customURL == "" {
		fmt.Println("--use-redirect requires a --custom-url")
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
		if len(pathParts) < 2 || pathParts[0] != "__pub__" {
			fmt.Println("Invalid public URL format. Expected /__pub__/<id>")
			os.Exit(1)
		}
		tunnelID = pathParts[1]
		tunnelSecret = *secret
	} else {
		serverURL = *server
		tunnelID = *id
		tunnelSecret = *secret
	}

	agent := &agentlib.Agent{
		ServerURL:        serverURL,
		LocalURL:         *local,
		ID:               tunnelID,
		Secret:           tunnelSecret,
		Protocol:         *protocol,
		Port:             *port,
		CustomURL:        *customURL,
		UseRedirect:      *useRedirect,
		DebugLog:         *debugLog,
		DebugFile:        *debugFile,
		RewriteRulesFile: *rewriteRulesFile,
	}

	// Run the agent (initialization is now handled automatically)
	ctx := context.Background()
	agent.Run(ctx)
}

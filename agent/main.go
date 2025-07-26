package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"gcp-proxy/pkg/agentlib"
)

func main() {
	server := flag.String("server", "", "Cloud Run base, e.g. https://<service>-<hash>-uc.a.run.app")
	publicURL := flag.String("public-url", "", "Public URL of the tunnel, e.g. https://<service>/pub/<id>")
	local := flag.String("local", "http://127.0.0.1:8080", "local http service")
	id := flag.String("id", "", "tunnel id (optional)")
	secret := flag.String("secret", "", "tunnel secret (optional)")
	flag.Parse()

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
	}

	agent.Run()
}

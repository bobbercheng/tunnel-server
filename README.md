CLOUD RUN REVERSE-TUNNEL HTTP PROXY (GO)
PLAIN TEXT README

⸻

	1.	OVERVIEW

⸻

This project implements a lightweight reverse-tunnel HTTP proxy using Google Cloud Run and Go.
	•	A Cloud Run “server” exposes a public URL: https:///pub/{tunnel_id}/…
	•	An on-prem/inside-network “agent” keeps a persistent WebSocket to the server.
	•	Every public HTTP request received by the server is forwarded through that WebSocket to the agent, which proxies it to your internal HTTP service and streams the response back.

This is faster and simpler than the Firestore/Cloud Functions long-polling approach because it uses a single, long-lived WebSocket connection for bidirectional messaging.

⸻

	2.	COMPONENTS

⸻

2.1 Server (Cloud Run)
	•	Endpoints:
	•	POST /register           -> returns {id, secret, public_url}
	•	GET  /ws?id=…&secret=…  -> WebSocket endpoint for agents
	•	ANY  /pub/{id}/…       -> Public HTTP entrypoint, forwarded to the agent
	•	Keeps in-memory maps for tunnels and active agents (PoC). For production, use Redis/Memorystore or Pub/Sub/NATS to share state across instances.

2.2 Agent (runs near your internal HTTP service)
	•	Registers to get tunnel id/secret/public_url
	•	Opens a WebSocket to /ws
	•	For each request frame, forwards to the local HTTP service and returns the response over the WebSocket

2.3 Message protocol (JSON over WebSocket)
Server -> Agent
{
“type”: “req”,
“req_id”: “…”,
“method”: “…”,
“path”: “…”,
“query”: “…”,
“headers”: { “Header”: [“Value”] },
“body”: “”
}
Agent -> Server
{
“type”: “resp”,
“req_id”: “…”,
“status”: 200,
“headers”: { “Header”: [“Value”] },
“body”: “”
}

⸻

	3.	DIRECTORY LAYOUT

⸻

server/
main.go
go.mod
Dockerfile

agent/
main.go
go.mod

⸻

	4.	PREREQUISITES

⸻

	•	Go 1.22+
	•	gcloud CLI
	•	A Google Cloud project with:
	•	Cloud Run API enabled
	•	Cloud Build API enabled
	•	Artifact Registry or Container Registry enabled (gcr.io or artifactregistry)
	•	(Optional) A custom domain mapped to the Cloud Run service if you want a stable PUBLIC_BASE_URL

⸻

	5.	QUICK START (MINIMAL: DO NOT SET PUBLIC_BASE_URL)

⸻

This path relies on the server code’s fallback to r.Host when PUBLIC_BASE_URL is not set.
	1.	Build and push the server image
export PROJECT_ID=your-project
export REGION=us-central1
gcloud builds submit –tag gcr.io/$PROJECT_ID/tunnel-server ./server
	2.	Deploy to Cloud Run
gcloud run deploy tunnel-server 
–image gcr.io/$PROJECT_ID/tunnel-server 
–platform managed 
–region $REGION 
–allow-unauthenticated 
–max-instances 1
Note: –max-instances=1 is recommended for this PoC, since state is in-memory.
	3.	Capture the service URL (shown after deploy). Example:
https://tunnel-server-abc123-uc.a.run.app
	4.	Run the agent next to your internal HTTP service
cd agent
go run . 
–server https://tunnel-server-abc123-uc.a.run.app 
–local  http://127.0.0.1:8080
The agent will:
	•	POST /register to get {id, secret, public_url}
	•	Print public_url (e.g. https://tunnel-server-abc123-uc.a.run.app/pub/)
	•	Open a WebSocket to /ws
	5.	Test
curl -i https://tunnel-server-abc123-uc.a.run.app/pub//
You should see the same response as your local service at http://127.0.0.1:8080/

⸻

	6.	OPTIONAL: SET PUBLIC_BASE_URL

⸻

You can set PUBLIC_BASE_URL to the Cloud Run URL (or a custom domain) so the server returns a stable public_url during registration.

Two-step approach:
	1.	Deploy without env var, capture the URL:
URL=$(gcloud run deploy tunnel-server 
–image gcr.io/$PROJECT_ID/tunnel-server 
–platform managed 
–region $REGION 
–allow-unauthenticated 
–max-instances 1 
–format=‘value(status.url)’)
	2.	Update the service:
gcloud run services update tunnel-server 
–platform managed 
–region $REGION 
–set-env-vars PUBLIC_BASE_URL=$URL

If you already have a custom domain bound (e.g. https://tunnel.yourdomain.com), set that directly at deploy time.

⸻

	7.	RUNNING THE AGENT AS A SERVICE (SYSTEMD EXAMPLE)

⸻

Example systemd unit (linux):

[Unit]
Description=Cloud Run Reverse Tunnel Agent
After=network-online.target

[Service]
User=youruser
ExecStart=/usr/local/bin/agent 
–server https://tunnel-server-abc123-uc.a.run.app 
–local  http://127.0.0.1:8080
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target

⸻

	8.	SECURITY NOTES

⸻

	•	Protect /register (IAM, mTLS, an API key, or a signed token).
	•	Consider signing every frame (HMAC) to prevent tampering.
	•	Rotate secrets and expire tunnels after inactivity.
	•	Optionally whitelist IPs or require JWTs on /pub or on /ws.

⸻

	9.	SCALING BEYOND ONE INSTANCE

⸻

	•	Replace all in-memory state (tunnels, agent connections, pending waiters) with:
	•	Redis/Memorystore to store tunnel metadata and map tunnel_id -> instance holding the WebSocket
	•	A message broker (Pub/Sub, NATS, Redis streams, Kafka) to route req/resp frames across instances
	•	Add sticky routing or a lookup service to find which instance holds a particular agent connection, then forward frames accordingly.
	•	Remove –max-instances=1 once state is externalized.

⸻

	10.	STREAMING AND LARGE BODIES

⸻

	•	The PoC sends entire request/response bodies as JSON (base64). For large bodies or streaming:
	•	Switch to binary frames
	•	Implement chunked frames (req-chunk, resp-chunk)
	•	Or upgrade to HTTP/2 (gRPC) or use raw TCP/WebSocket binary streams without JSON

⸻

	11.	OBSERVABILITY

⸻

	•	Log a unique req_id for every proxied request
	•	Add metrics (request count, latency, error rate)
	•	Add tracing (OpenTelemetry) to tie public requests to internal forwarding

⸻

	12.	COMMON TROUBLESHOOTING

⸻

Symptom: curl to /pub/ returns 502 or “agent not connected”
Cause: Agent not connected or crashed. Check agent logs.

Symptom: timeout waiting agent
Cause: Internal HTTP service slow or not reachable. Increase timeouts or verify service.

Symptom: 401 unauthorized on /ws
Cause: Wrong id/secret pair. Delete the tunnel, register again.

Symptom: Multiple agents for the same id bouncing
Cause: PoC doesn’t coordinate multi-connect properly. Avoid multiple agents for the same id or implement locking with Redis.

⸻

	13.	CLEANUP

⸻

	•	Delete the Cloud Run service:
gcloud run services delete tunnel-server –platform managed –region $REGION
	•	Delete the image:
gcloud artifacts docker images delete gcr.io/$PROJECT_ID/tunnel-server:latest (or use Container Registry equivalent)

⸻

	14.	LICENSE

⸻

Add your preferred license (MIT/Apache-2.0/etc.) if you plan to open-source.

⸻

	15.	NEXT STEPS

⸻

	•	Replace in-memory maps with Redis or Pub/Sub to scale horizontally
	•	Add authentication and authorization layers
	•	Support streaming/chunked messages
	•	Add health checks and graceful shutdown logic
	•	Package the agent as a static binary and provide Docker images for both sides
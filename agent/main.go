package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

type RegisterResp struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	PublicURL string `json:"public_url"`
}

type ReqFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

type RespFrame struct {
	Type    string              `json:"type"`
	ReqID   string              `json:"req_id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// Usage: cd agent
// go run . \
// --server https://tunnel-server-3w6u4kmniq-ue.a.run.app \
// --local http://127.0.0.1:8080

func main() {
	server := flag.String("server", "", "Cloud Run base, e.g. https://<service>-<hash>-uc.a.run.app")
	local := flag.String("local", "http://127.0.0.1:8080", "local http service")
	id := flag.String("id", "", "tunnel id (optional)")
	secret := flag.String("secret", "", "tunnel secret (optional)")
	flag.Parse()

	if *server == "" {
		fmt.Println("--server is required")
		os.Exit(1)
	}

	if *id == "" || *secret == "" {
		reg, err := register(*server)
		if err != nil {
			panic(err)
		}
		*id, *secret = reg.ID, reg.Secret
		fmt.Println("public_url:", reg.PublicURL)
	}

	for {
		if err := runOnce(*server, *local, *id, *secret); err != nil {
			fmt.Printf("agent loop error: %v\n", err)

			// Check if it's a websocket close error and handle it gracefully
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
				websocket.CloseStatus(err) == websocket.StatusGoingAway {
				fmt.Println("websocket closed normally, reconnecting...")
			} else {
				fmt.Printf("unexpected error: %v, reconnecting...\n", err)
			}
		}
		// backoff
		time.Sleep(2 * time.Second)
	}
}

func runOnce(server, local, id, secret string) error {
	ctx := context.Background()
	wsURL := fmt.Sprintf("%s/ws?id=%s&secret=%s", server, url.QueryEscape(id), url.QueryEscape(secret))
	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return err
	}
	defer ws.Close(websocket.StatusInternalError, "internal")

	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			continue
		}
		var req ReqFrame
		if err := json.Unmarshal(data, &req); err != nil {
			continue
		}
		if req.Type != "req" {
			continue
		}

		status, hdr, body, ferr := forward(local, &req)

		resp := RespFrame{
			Type:    "resp",
			ReqID:   req.ReqID,
			Status:  status,
			Headers: hdr,
			Body:    body,
		}
		if ferr != nil {
			resp.Status = http.StatusBadGateway
			resp.Headers = map[string][]string{"Content-Type": {"text/plain"}}
			resp.Body = []byte(ferr.Error())
		}
		if err := ws.Write(ctx, websocket.MessageText, mustJSON(resp)); err != nil {
			return err
		}
	}
}

func forward(local string, rd *ReqFrame) (int, map[string][]string, []byte, error) {
	target := local + rd.Path
	if rd.Query != "" {
		target += "?" + rd.Query
	}
	req, err := http.NewRequest(rd.Method, target, bytes.NewReader(rd.Body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, vs := range rd.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	// Use a longer timeout for streaming responses
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	// Handle streaming responses (like SSE) differently
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "text/stream") ||
		strings.Contains(contentType, "application/stream") {
		// For streaming responses, read with a buffer and timeout
		return handleStreamingResponse(resp)
	}

	// For regular responses, read all at once
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, b, nil
}

func handleStreamingResponse(resp *http.Response) (int, map[string][]string, []byte, error) {
	// Create a buffer to collect the streaming data
	var buffer bytes.Buffer

	// Create a context with timeout for reading the stream
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Channel to signal completion
	done := make(chan error, 1)

	go func() {
		defer close(done)

		// Read the stream in chunks with timeout
		buf := make([]byte, 4096)
		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			default:
				n, err := resp.Body.Read(buf)
				if n > 0 {
					buffer.Write(buf[:n])
				}
				if err != nil {
					if err == io.EOF {
						done <- nil // Normal end of stream
						return
					}
					done <- err
					return
				}
			}
		}
	}()

	// Wait for completion or timeout
	err := <-done
	if err != nil && err != context.DeadlineExceeded {
		return resp.StatusCode, resp.Header, buffer.Bytes(), nil // Return what we have
	}

	return resp.StatusCode, resp.Header, buffer.Bytes(), nil
}

func register(server string) (*RegisterResp, error) {
	resp, err := http.Post(server+"/register", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r RegisterResp
	return &r, json.NewDecoder(resp.Body).Decode(&r)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

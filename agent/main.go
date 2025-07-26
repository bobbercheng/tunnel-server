package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

var errUnauthorized = errors.New("unauthorized: credentials rejected by server")

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

	currentID := *id
	currentSecret := *secret

	if currentID == "" || currentSecret == "" {
		fmt.Println("No tunnel id/secret provided, registering new tunnel...")
		reg, err := register(*server)
		if err != nil {
			fmt.Println("FATAL: initial registration failed:", err)
			os.Exit(1)
		}
		currentID, currentSecret = reg.ID, reg.Secret
		fmt.Println("Registered successfully!")
		fmt.Println("  ID:", currentID)
		fmt.Println("  Secret:", currentSecret)
		fmt.Println("  Public URL:", reg.PublicURL)
	}

	for {
		err := runOnce(*server, *local, currentID, currentSecret)
		if err == nil {
			fmt.Println("Connection closed. Reconnecting in 2 seconds...")
			time.Sleep(2 * time.Second)
			continue
		}

		if errors.Is(err, errUnauthorized) {
			fmt.Println("Credentials rejected, re-registering for a new tunnel...")
			reg, regErr := register(*server)
			if regErr != nil {
				fmt.Println("Failed to re-register:", regErr)
				fmt.Println("Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			}
			currentID, currentSecret = reg.ID, reg.Secret
			fmt.Println("Re-registered successfully!")
			fmt.Println("  ID:", currentID)
			fmt.Println("  Secret:", currentSecret)
			fmt.Println("  New Public URL:", reg.PublicURL)
			continue
		}

		fmt.Printf("Connection error: %v\n", err)
		fmt.Println("Reconnecting in 2 seconds...")
		time.Sleep(2 * time.Second)
	}
}

func runOnce(server, local, id, secret string) error {
	dialCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wsURL := fmt.Sprintf("%s/ws?id=%s&secret=%s", server, url.QueryEscape(id), url.QueryEscape(secret))
	ws, resp, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return errUnauthorized
			}
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("handshake failed with status %d: %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("dial error: %w", err)
	}
	defer ws.Close(websocket.StatusInternalError, "internal error")
	fmt.Println("Connection established successfully.")

	readCtx := context.Background()
	for {
		typ, data, err := ws.Read(readCtx)
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

		go func() {
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
			if err := ws.Write(context.Background(), websocket.MessageText, mustJSON(resp)); err != nil {
				fmt.Printf("Error writing response for req_id %s: %v\n", req.ReqID, err)
			}
		}()
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

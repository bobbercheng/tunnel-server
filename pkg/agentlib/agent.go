package agentlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

var ErrUnauthorized = errors.New("unauthorized: credentials rejected by server")

type Agent struct {
	ServerURL string
	LocalURL  string
	ID        string
	Secret    string
}

func (a *Agent) Run() {
	if a.ID == "" || a.Secret == "" {
		fmt.Println("No tunnel id/secret provided, registering new tunnel...")
		reg, err := a.register()
		if err != nil {
			fmt.Println("FATAL: initial registration failed:", err)
			return
		}
		a.ID, a.Secret = reg.ID, reg.Secret
		fmt.Println("Registered successfully!")
		fmt.Println("  ID:", a.ID)
		fmt.Println("  Secret:", a.Secret)
		fmt.Println("  Public URL:", reg.PublicURL)
	}

	for {
		err := a.runOnce()
		if err == nil {
			fmt.Println("Connection closed. Reconnecting in 2 seconds...")
			time.Sleep(2 * time.Second)
			continue
		}

		if errors.Is(err, ErrUnauthorized) {
			fmt.Println("Credentials rejected, re-registering for a new tunnel...")
			reg, regErr := a.register()
			if regErr != nil {
				fmt.Println("Failed to re-register:", regErr)
				fmt.Println("Retrying in 5 seconds...")
				time.Sleep(5 * time.Second)
				continue
			}
			a.ID, a.Secret = reg.ID, reg.Secret
			fmt.Println("Re-registered successfully!")
			fmt.Println("  ID:", a.ID)
			fmt.Println("  Secret:", a.Secret)
			fmt.Println("  New Public URL:", reg.PublicURL)
			continue
		}

		fmt.Printf("Connection error: %v\n", err)
		fmt.Println("Reconnecting in 2 seconds...")
		time.Sleep(2 * time.Second)
	}
}

func (a *Agent) runOnce() error {
	dialCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wsURL := fmt.Sprintf("%s/ws?id=%s&secret=%s", a.ServerURL, url.QueryEscape(a.ID), url.QueryEscape(a.Secret))
	ws, resp, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return ErrUnauthorized
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
			status, hdr, body, ferr := a.forward(&req)

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

func (a *Agent) forward(rd *ReqFrame) (int, map[string][]string, []byte, error) {
	target := a.LocalURL + rd.Path
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

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/event-stream") ||
		strings.Contains(contentType, "text/stream") ||
		strings.Contains(contentType, "application/stream") {
		return handleStreamingResponse(resp)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, b, nil
}

func handleStreamingResponse(resp *http.Response) (int, map[string][]string, []byte, error) {
	var buffer bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		defer close(done)
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
						done <- nil
						return
					}
					done <- err
					return
				}
			}
		}
	}()

	err := <-done
	if err != nil && err != context.DeadlineExceeded {
		return resp.StatusCode, resp.Header, buffer.Bytes(), nil
	}
	return resp.StatusCode, resp.Header, buffer.Bytes(), nil
}

func (a *Agent) register() (*RegisterResp, error) {
	resp, err := http.Post(a.ServerURL+"/register", "application/json", nil)
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

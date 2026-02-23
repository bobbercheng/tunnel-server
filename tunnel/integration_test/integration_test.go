// Package integration_test validates the unified protocol proxy end-to-end.
//
// It starts three components:
//  1. A test web app (regular HTTP, SSE, chunked, WebSocket endpoints)
//  2. The tunnel server (built binary)
//  3. The tunnel agent (built binary, connecting server → test web app)
//
// Then it sends requests through the tunnel and validates each response type
// works correctly without any special-casing.
package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// getFreePort returns an available TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// buildBinary compiles a Go module and returns the path to the binary.
func buildBinary(t *testing.T, srcDir, name string) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = srcDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s failed: %v\n%s", name, err, out)
	}
	return binPath
}

// startTestApp starts a local HTTP server with various endpoint types.
func startTestApp(t *testing.T, port int) {
	t.Helper()

	mux := http.NewServeMux()

	// Regular HTTP endpoint
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		json.NewEncoder(w).Encode(map[string]string{"message": "hello world"})
	})

	// POST endpoint — echoes body back
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
		io.Copy(w, r.Body)
	})

	// SSE endpoint — sends 5 events then closes
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		w.WriteHeader(200)
		flusher.Flush()

		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})

	// Chunked endpoint — sends multiple chunks
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "chunk-%d\n", i)
			flusher.Flush()
			time.Sleep(50 * time.Millisecond)
		}
	})

	// Large response endpoint — tests multi-chunk body relay
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// Send 100KB of data (larger than the 32KB chunk size)
		data := strings.Repeat("X", 100*1024)
		w.Write([]byte(data))
	})

	// WebSocket endpoint — echoes messages back with prefix
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		ctx := r.Context()
		for {
			msgType, msg, err := conn.Read(ctx)
			if err != nil {
				return
			}
			reply := "echo:" + string(msg)
			if err := conn.Write(ctx, msgType, []byte(reply)); err != nil {
				return
			}
		}
	})

	// 404 handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	go srv.ListenAndServe()
	t.Cleanup(func() {
		srv.Close()
	})
}

// waitForReady polls a URL until it returns 200 or the timeout expires.
func waitForReady(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", url)
}

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	projectRoot := ".."

	// Build server and agent binaries first — avoids `go run` subprocess issues
	// with process cleanup (WaitDelay, orphaned child processes).
	t.Log("Building server and agent binaries...")
	serverBin := buildBinary(t, projectRoot+"/server", "server")
	agentBin := buildBinary(t, projectRoot+"/agent", "agent")
	t.Log("Binaries built successfully")

	// Allocate ports
	appPort := getFreePort(t)
	serverPort := getFreePort(t)

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	localURL := fmt.Sprintf("http://127.0.0.1:%d", appPort)

	// 1. Start test web app
	startTestApp(t, appPort)
	if err := waitForReady(localURL+"/hello", 5*time.Second); err != nil {
		t.Fatalf("test app failed to start: %v", err)
	}
	t.Log("Test app started on", localURL)

	// 2. Start tunnel server
	serverCmd := exec.Command(serverBin)
	serverCmd.Env = append(os.Environ(),
		fmt.Sprintf("PORT=%d", serverPort),
		fmt.Sprintf("SERVER_URL=%s", serverURL),
	)
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	t.Cleanup(func() {
		serverCmd.Process.Signal(syscall.SIGTERM)
		serverCmd.Process.Kill()
		serverCmd.Wait()
	})
	if err := waitForReady(serverURL+"/__health__", 5*time.Second); err != nil {
		t.Fatalf("server failed to start: %v", err)
	}
	t.Log("Tunnel server started on", serverURL)

	// 3. Start tunnel agent — capture stdout to get the public URL
	agentCmd := exec.Command(agentBin,
		"--server", serverURL,
		"--local", localURL,
	)
	agentStdout, _ := agentCmd.StdoutPipe()
	agentCmd.Stderr = os.Stderr
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	t.Cleanup(func() {
		agentCmd.Process.Signal(syscall.SIGTERM)
		agentCmd.Process.Kill()
		agentCmd.Wait()
	})

	// Parse agent output to find the public URL.
	// The goroutine keeps draining stdout so cmd.Wait() doesn't hang on pipe I/O.
	var publicURL string
	scanner := bufio.NewScanner(agentStdout)
	urlCh := make(chan string, 1)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "/__pub__/") && strings.HasPrefix(trimmed, "http") {
				select {
				case urlCh <- trimmed:
				default:
				}
			}
		}
	}()

	select {
	case publicURL = <-urlCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for agent to print public URL")
	}

	t.Logf("Agent registered, public URL: %s", publicURL)

	// Give the tunnel a moment to stabilize
	time.Sleep(500 * time.Millisecond)

	// --- Run tests ---

	t.Run("regular_http_get", func(t *testing.T) {
		resp, err := http.Get(publicURL + "hello")
		if err != nil {
			t.Fatalf("GET /hello failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("expected Content-Type application/json, got %s", ct)
		}
		if hdr := resp.Header.Get("X-Custom-Header"); hdr != "test-value" {
			t.Fatalf("expected X-Custom-Header=test-value, got %s", hdr)
		}

		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["message"] != "hello world" {
			t.Fatalf("expected 'hello world', got '%s'", body["message"])
		}
	})

	t.Run("http_post_echo", func(t *testing.T) {
		payload := `{"key":"value","number":42}`
		resp, err := http.Post(publicURL+"echo", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /echo failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		if string(bodyBytes) != payload {
			t.Fatalf("expected echoed payload, got '%s'", string(bodyBytes))
		}
	})

	t.Run("sse_streaming", func(t *testing.T) {
		req, _ := http.NewRequest("GET", publicURL+"sse", nil)
		req.Header.Set("Accept", "text/event-stream")
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /sse failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
			t.Fatalf("expected Content-Type text/event-stream, got %s", ct)
		}

		// Read all SSE events
		body, _ := io.ReadAll(resp.Body)
		content := string(body)
		for i := 0; i < 5; i++ {
			expected := fmt.Sprintf("data: event-%d", i)
			if !strings.Contains(content, expected) {
				t.Fatalf("missing SSE event %d in response: %s", i, content)
			}
		}
	})

	t.Run("chunked_response", func(t *testing.T) {
		resp, err := http.Get(publicURL + "chunked")
		if err != nil {
			t.Fatalf("GET /chunked failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		content := string(body)
		for i := 0; i < 3; i++ {
			expected := fmt.Sprintf("chunk-%d", i)
			if !strings.Contains(content, expected) {
				t.Fatalf("missing chunk %d in response: %s", i, content)
			}
		}
	})

	t.Run("large_response", func(t *testing.T) {
		resp, err := http.Get(publicURL + "large")
		if err != nil {
			t.Fatalf("GET /large failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		expected := 100 * 1024
		if len(body) != expected {
			t.Fatalf("expected %d bytes, got %d", expected, len(body))
		}
	})

	t.Run("websocket_echo", func(t *testing.T) {
		wsURL := strings.Replace(publicURL, "http://", "ws://", 1) + "ws"
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, _, err := websocket.Dial(ctx, wsURL, nil)
		if err != nil {
			t.Fatalf("WebSocket dial failed: %v", err)
		}
		defer conn.Close(websocket.StatusNormalClosure, "")

		// Wait for the agent to establish the local WS connection.
		// The server sends ws_open to the agent which then dials the local
		// service — this takes a moment.
		time.Sleep(500 * time.Millisecond)

		// Send and receive 3 messages
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("test-message-%d", i)
			if err := conn.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
				t.Fatalf("WS write failed: %v", err)
			}

			_, reply, err := conn.Read(ctx)
			if err != nil {
				t.Fatalf("WS read failed: %v", err)
			}

			expected := "echo:" + msg
			if string(reply) != expected {
				t.Fatalf("expected '%s', got '%s'", expected, string(reply))
			}
		}
	})

	t.Run("404_passthrough", func(t *testing.T) {
		resp, err := http.Get(publicURL + "nonexistent-path")
		if err != nil {
			t.Fatalf("GET /nonexistent-path failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 404 {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})
}

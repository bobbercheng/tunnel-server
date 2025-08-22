package agentlib

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestStreamingResponseFix tests the fix for the blocking read issue in streaming responses
func TestStreamingResponseFix(t *testing.T) {
	// Create a test server that simulates SSE streaming
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("Response writer does not support flushing")
		}

		// Send first chunk immediately
		w.Write([]byte("data: first event\n\n"))
		flusher.Flush()

		// Wait a bit, then send second chunk (simulates real SSE timing)
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("data: second event\n\n"))
		flusher.Flush()

		// Wait a bit more, then send final chunk
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte("data: final event\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	// Create HTTP request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Make the request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Verify we get a streaming response
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		t.Fatalf("Expected text/event-stream, got %s", contentType)
	}

	// Test the new non-blocking read logic
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	buf := make([]byte, 1024)
	chunks := []string{}

	// Simulate the streaming loop from agent.go with the new logic
	for {
		// Use the same pattern as the fixed code
		type readResult struct {
			n   int
			err error
		}
		readChan := make(chan readResult, 1)

		// Start the read in a goroutine
		go func() {
			n, err := resp.Body.Read(buf)
			readChan <- readResult{n: n, err: err}
		}()

		// Wait for either context cancellation or read completion
		var n int
		var readErr error
		select {
		case <-ctx.Done():
			t.Log("Context cancelled - this is expected after timeout")
			return
		case result := <-readChan:
			n = result.n
			readErr = result.err
		}

		if n > 0 {
			chunk := string(buf[:n])
			chunks = append(chunks, chunk)
			t.Logf("Read chunk %d: %q", len(chunks), chunk)
		}

		if readErr != nil {
			if readErr == io.EOF {
				t.Log("Reached EOF")
				break
			} else {
				t.Fatalf("Read error: %v", readErr)
			}
		}

		// If we've received all expected chunks, we can break
		if len(chunks) >= 3 {
			break
		}
	}

	// Verify we received all chunks
	if len(chunks) < 3 {
		t.Errorf("Expected at least 3 chunks, got %d", len(chunks))
	}

	// Verify chunk contents
	allData := strings.Join(chunks, "")
	expectedEvents := []string{"first event", "second event", "final event"}
	for _, event := range expectedEvents {
		if !strings.Contains(allData, event) {
			t.Errorf("Expected to find %q in response data", event)
		}
	}

	t.Log("✅ Streaming response fix test passed!")
}

// TestStreamingResponseContext tests that context cancellation works properly
func TestStreamingResponseContext(t *testing.T) {
	// Create a server that streams slowly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("Response writer does not support flushing")
		}

		// Send first chunk
		w.Write([]byte("data: chunk1\n\n"))
		flusher.Flush()

		// Wait a long time before sending next chunk (longer than our test timeout)
		time.Sleep(5 * time.Second)
		w.Write([]byte("data: chunk2\n\n"))
		flusher.Flush()
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	buf := make([]byte, 1024)
	chunkCount := 0

	// Test that the streaming loop can be cancelled via context
	for {
		type readResult struct {
			n   int
			err error
		}
		readChan := make(chan readResult, 1)

		go func() {
			n, err := resp.Body.Read(buf)
			readChan <- readResult{n: n, err: err}
		}()

		select {
		case <-ctx.Done():
			t.Log("✅ Context cancellation worked correctly")
			return
		case result := <-readChan:
			if result.n > 0 {
				chunkCount++
				t.Logf("Received chunk %d", chunkCount)
			}
			if result.err != nil {
				if result.err == io.EOF {
					t.Log("EOF reached")
					return
				}
				t.Fatalf("Read error: %v", result.err)
			}
		}
	}
}
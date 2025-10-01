package agentlib

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// handleStreamingResponseDirect handles streaming directly with the original response
func (a *Agent) handleStreamingResponseDirectNew(ctx context.Context, req *ReqFrame, resp *http.Response, writeEncrypted func(v any) error) {
	defer resp.Body.Close()

	log.Printf("AGENT STREAMING: Stream established directly | ReqID: %s | Status: %d | ContentType: %s",
		req.ReqID, resp.StatusCode, resp.Header.Get("Content-Type"))

	// DIAGNOSTIC: Log all headers received from local service
	log.Printf("AGENT STREAMING: All headers from local service | ReqID: %s | Headers: %+v", req.ReqID, resp.Header)

	// DIAGNOSTIC: Check if content-type is what we expect for streaming
	contentType := resp.Header.Get("Content-Type")
	log.Printf("AGENT STREAMING: Content-Type analysis | ReqID: %s | ContentType: '%s' | IsEventStream: %v | IsStream: %v",
		req.ReqID, contentType,
		strings.Contains(contentType, "text/event-stream"),
		strings.Contains(contentType, "text/stream") || strings.Contains(contentType, "application/stream"))

	// Send streaming start message with headers and status
	startFrame := ChunkedRespFrame{
		Type:        "streaming_start",
		ReqID:       req.ReqID,
		Status:      resp.StatusCode,
		Headers:     resp.Header,
		ChunkIndex:  0,
		TotalChunks: -1, // Unknown for streaming
		Data:        []byte{},
		IsLast:      false,
	}

	// DIAGNOSTIC: Log what we're sending in the streaming_start frame
	log.Printf("AGENT STREAMING: Sending streaming_start frame | ReqID: %s | Headers: %+v", req.ReqID, startFrame.Headers)

	if err := writeEncrypted(startFrame); err != nil {
		log.Printf("AGENT STREAMING: Failed to send streaming_start | ReqID: %s | Error: %v", req.ReqID, err)
		return
	}

	// Stream data in real-time with connection health monitoring
	buf := make([]byte, 32768) // Increased from 4KB to 32KB for better streaming
	chunkIndex := 1

	log.Printf("AGENT STREAMING: Starting stream loop | ReqID: %s | BufferSize: %d", req.ReqID, len(buf))

	// Add connection health monitoring
	lastWriteTime := time.Now()
	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()

	// Start health monitoring in a separate goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				log.Printf("AGENT STREAMING: Health check timer triggered | ReqID: %s", req.ReqID)
				// Check if we're still able to write to the WebSocket
				if time.Since(lastWriteTime) > 30*time.Second {
					log.Printf("AGENT STREAMING: No writes in 30s, checking connection health | ReqID: %s", req.ReqID)
					// Try to send a heartbeat to check connection
					heartbeat := ChunkedRespFrame{
						Type:        "streaming_heartbeat",
						ReqID:       req.ReqID,
						Status:      resp.StatusCode,
						Headers:     nil,
						ChunkIndex:  -1, // Special index for heartbeat
						TotalChunks: -1,
						Data:        []byte("heartbeat"),
						IsLast:      false,
					}
					if err := writeEncrypted(heartbeat); err != nil {
						log.Printf("AGENT STREAMING: Connection health check failed | ReqID: %s | Error: %v", req.ReqID, err)
						return
					}
					log.Printf("AGENT STREAMING: Connection health check passed | ReqID: %s", req.ReqID)
				}
			}
		}
	}()

	// Main streaming loop with non-blocking reads using goroutine and channels
	for {
		log.Printf("AGENT STREAMING: Starting loop iteration | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)

		// Use a channel to make the read interruptible
		type readResult struct {
			n   int
			err error
		}
		readChan := make(chan readResult, 1)

		// Start the read in a goroutine
		go func() {
			log.Printf("AGENT STREAMING: About to read from response body (BLOCKING) | ReqID: %s | Attempt: %d", req.ReqID, chunkIndex)
			n, err := resp.Body.Read(buf)
			log.Printf("AGENT STREAMING: Read operation completed | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			readChan <- readResult{n: n, err: err}
		}()

		// Wait for either context cancellation, timeout, or read completion
		var n int
		var err error

		// Add a timeout for debugging slow reads
		readTimeout := time.NewTimer(10 * time.Second)
		defer readTimeout.Stop()

		select {
		case <-ctx.Done():
			log.Printf("AGENT STREAMING: Context cancelled | ReqID: %s", req.ReqID)
			return
		case <-readTimeout.C:
			log.Printf("AGENT STREAMING: Read timeout after 10s, continuing to wait | ReqID: %s | ChunkIndex: %d", req.ReqID, chunkIndex)
			// Don't return, continue waiting for the read
			select {
			case <-ctx.Done():
				log.Printf("AGENT STREAMING: Context cancelled during timeout wait | ReqID: %s", req.ReqID)
				return
			case result := <-readChan:
				n = result.n
				err = result.err
				log.Printf("AGENT STREAMING: Read completed after timeout | ReqID: %s | BytesRead: %d | Error: %v", req.ReqID, n, err)
			}
		case result := <-readChan:
			n = result.n
			err = result.err
			log.Printf("AGENT STREAMING: Read from response body | ReqID: %s | BytesRead: %d | Error: %v | BufferSize: %d", req.ReqID, n, err, len(buf))
		}

		if n > 0 {
			log.Printf("AGENT STREAMING: Processing chunk with %d bytes | ReqID: %s", n, req.ReqID)
			// Send chunk immediately
			chunkFrame := ChunkedRespFrame{
				Type:        "streaming_chunk",
				ReqID:       req.ReqID,
				Status:      resp.StatusCode,
				Headers:     nil, // Headers only sent in start frame
				ChunkIndex:  chunkIndex,
				TotalChunks: -1, // Unknown for streaming
				Data:        make([]byte, n),
				IsLast:      false,
			}
			copy(chunkFrame.Data, buf[:n])

			log.Printf("AGENT STREAMING: About to send chunk %d | ReqID: %s | Size: %d bytes", chunkIndex, req.ReqID, n)

			if err := writeEncrypted(chunkFrame); err != nil {
				log.Printf("AGENT STREAMING: Failed to send chunk %d | ReqID: %s | Error: %v", chunkIndex, req.ReqID, err)
				return
			}

			log.Printf("AGENT STREAMING: Sent chunk %d (%d bytes) | ReqID: %s", chunkIndex, n, req.ReqID)
			chunkIndex++
			lastWriteTime = time.Now() // Update last write time
		}

		if err != nil {
			if err == io.EOF {
				// Stream ended normally
				log.Printf("AGENT STREAMING: Stream ended with EOF | ReqID: %s | TotalChunks: %d", req.ReqID, chunkIndex)
				endFrame := ChunkedRespFrame{
					Type:        "streaming_end",
					ReqID:       req.ReqID,
					Status:      resp.StatusCode,
					Headers:     nil,
					ChunkIndex:  chunkIndex,
					TotalChunks: chunkIndex,
					Data:        []byte{},
					IsLast:      true,
				}

				if err := writeEncrypted(endFrame); err != nil {
					log.Printf("AGENT STREAMING: Failed to send streaming_end | ReqID: %s | Error: %v", req.ReqID, err)
				} else {
					log.Printf("AGENT STREAMING: Stream completed successfully | ReqID: %s | TotalChunks: %d", req.ReqID, chunkIndex)
				}
				return
			} else {
				// Stream error
				log.Printf("AGENT STREAMING: Stream read error | ReqID: %s | Error: %v", req.ReqID, err)
				return
			}
		}
	}
}

// handleChunkedResponse processes chunked responses
func (a *Agent) handleChunkedResponseNew(chunk *ChunkedRespFrame, writeEncrypted func(v any) error) {
	a.chunkedRespMu.Lock()
	defer a.chunkedRespMu.Unlock()

	// Get or create chunked response tracker
	resp, exists := a.chunkedResps[chunk.ReqID]
	if !exists {
		resp = &ChunkedResponse{
			Status:         chunk.Status,
			Headers:        chunk.Headers,
			Chunks:         make([][]byte, chunk.TotalChunks),
			ReceivedChunks: make(map[int][]byte),
			TotalChunks:    chunk.TotalChunks,
		}
		a.chunkedResps[chunk.ReqID] = resp
	}

	// Store chunk data
	if len(chunk.Data) > 0 {
		resp.Chunks[chunk.ChunkIndex] = chunk.Data
		resp.ReceivedChunks[chunk.ChunkIndex] = chunk.Data
		resp.ReceivedCount++
	}

	log.Printf("CHUNKED: Received chunk %d/%d for request %s | Size: %d bytes",
		chunk.ChunkIndex, chunk.TotalChunks, chunk.ReqID, len(chunk.Data))

	// Check if we have all chunks
	if chunk.IsLast || (resp.TotalChunks > 0 && resp.ReceivedCount >= resp.TotalChunks) {
		// Reconstruct complete response
		var body []byte
		for i := 1; i <= resp.TotalChunks; i++ {
			if chunkData, exists := resp.ReceivedChunks[i]; exists {
				body = append(body, chunkData...)
			}
		}

		// Send complete response
		finalResp := RespFrame{
			Type:    "resp",
			ReqID:   chunk.ReqID,
			Status:  resp.Status,
			Headers: resp.Headers,
			Body:    body,
		}

		if err := writeEncrypted(finalResp); err != nil {
			log.Printf("CHUNKED: Failed to send complete response for %s: %v", chunk.ReqID, err)
		} else {
			log.Printf("CHUNKED: Sent complete response for %s | TotalSize: %d bytes", chunk.ReqID, len(body))
		}

		// Clean up
		delete(a.chunkedResps, chunk.ReqID)
	}
}
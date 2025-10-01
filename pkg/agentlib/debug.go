package agentlib

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// getDebugFileNameNew returns the debug log file name
func (a *Agent) getDebugFileNameNew() string {
	if a.DebugFile != "" {
		return a.DebugFile
	}
	if a.ID != "" {
		return fmt.Sprintf("debug_%s.log", a.ID)
	}
	return "debug_unknown.log"
}

// initDebugLoggingNew sets up debug logging to file
func (a *Agent) initDebugLoggingNew() error {
	if !a.DebugLog {
		return nil
	}

	fileName := a.getDebugFileNameNew()
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open debug log file %s: %v", fileName, err)
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	// Close existing file if any
	if a.debugLogFile != nil {
		a.debugLogFile.Close()
	}

	a.debugLogFile = file

	// Write session start marker
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	header := fmt.Sprintf("\n=== DEBUG SESSION START: %s ===\n", timestamp)
	_, err = a.debugLogFile.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write debug log header: %v", err)
	}

	return nil
}

// logDebugRequestNew logs request details to debug file
func (a *Agent) logDebugRequestNew(req *ReqFrame) {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	var logEntry strings.Builder
	logEntry.WriteString(fmt.Sprintf("\n--- REQUEST %s ---\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Tunnel ID: %s\n", a.ID))
	logEntry.WriteString(fmt.Sprintf("Request ID: %s\n", req.ReqID))
	logEntry.WriteString(fmt.Sprintf("Method: %s\n", req.Method))
	logEntry.WriteString(fmt.Sprintf("Path: %s\n", req.Path))
	if req.Query != "" {
		logEntry.WriteString(fmt.Sprintf("Query: %s\n", req.Query))
	}

	logEntry.WriteString("Headers:\n")
	for name, values := range req.Headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}

	if len(req.Body) > 0 {
		logEntry.WriteString(fmt.Sprintf("Body Length: %d bytes\n", len(req.Body)))
		// Log body content (truncated if too large)
		bodyStr := string(req.Body)
		if len(bodyStr) > 1000 {
			bodyStr = bodyStr[:1000] + "... (truncated)"
		}
		logEntry.WriteString(fmt.Sprintf("Body Content:\n%s\n", bodyStr))
	}

	a.debugLogFile.WriteString(logEntry.String())
	a.debugLogFile.Sync() // Force write to disk
}

// logDebugResponseNew logs response details to debug file
func (a *Agent) logDebugResponseNew(resp *RespFrame) {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	var logEntry strings.Builder
	logEntry.WriteString(fmt.Sprintf("\n--- RESPONSE %s ---\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Tunnel ID: %s\n", a.ID))
	logEntry.WriteString(fmt.Sprintf("Request ID: %s\n", resp.ReqID))
	logEntry.WriteString(fmt.Sprintf("Status: %d\n", resp.Status))

	logEntry.WriteString("Headers:\n")
	for name, values := range resp.Headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}

	if len(resp.Body) > 0 {
		logEntry.WriteString(fmt.Sprintf("Body Length: %d bytes\n", len(resp.Body)))
		// Log body content (truncated if too large and non-binary)
		if isBinaryContentNew(resp.Headers) {
			logEntry.WriteString("Body Content: [Binary data]\n")
		} else {
			bodyStr := string(resp.Body)
			if len(bodyStr) > 1000 {
				bodyStr = bodyStr[:1000] + "... (truncated)"
			}
			logEntry.WriteString(fmt.Sprintf("Body Content:\n%s\n", bodyStr))
		}
	}

	a.debugLogFile.WriteString(logEntry.String())
	a.debugLogFile.Sync() // Force write to disk
}

// isBinaryContentNew checks if the content is binary based on headers
func isBinaryContentNew(headers map[string][]string) bool {
	if contentType, exists := headers["Content-Type"]; exists && len(contentType) > 0 {
		ct := strings.ToLower(contentType[0])
		return strings.Contains(ct, "image/") ||
			strings.Contains(ct, "video/") ||
			strings.Contains(ct, "audio/") ||
			strings.Contains(ct, "application/octet-stream") ||
			strings.Contains(ct, "application/pdf")
	}
	return false
}

// closeDebugLoggingNew closes the debug log file if open
func (a *Agent) closeDebugLoggingNew() {
	if !a.DebugLog || a.debugLogFile == nil {
		return
	}

	a.debugLogMu.Lock()
	defer a.debugLogMu.Unlock()

	// Write session end marker
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	footer := fmt.Sprintf("\n=== DEBUG SESSION END: %s ===\n", timestamp)
	a.debugLogFile.WriteString(footer)
	a.debugLogFile.Sync()

	// Close the file
	a.debugLogFile.Close()
	a.debugLogFile = nil
}
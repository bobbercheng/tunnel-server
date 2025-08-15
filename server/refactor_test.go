package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBasicFunctionality tests that the refactored code compiles and basic functions work
func TestBasicFunctionality(t *testing.T) {
	// Test client tracker creation
	tracker := NewClientTracker()
	if tracker == nil {
		t.Fatal("Failed to create client tracker")
	}

	// Test custom URL validation
	if err := validateCustomURL("valid-url"); err != nil {
		t.Errorf("Valid URL rejected: %v", err)
	}

	if err := validateCustomURL("__health__"); err == nil {
		t.Error("Reserved path should be rejected")
	}

	// Test fingerprinting
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	
	fingerprint := extractFingerprint(req)
	if fingerprint == nil {
		t.Fatal("Failed to extract fingerprint")
	}
	
	if fingerprint.UserAgent != "test-agent" {
		t.Errorf("Expected User-Agent test-agent, got %s", fingerprint.UserAgent)
	}
	
	if fingerprint.ClientIP != "1.2.3.4" {
		t.Errorf("Expected IP 1.2.3.4, got %s", fingerprint.ClientIP)
	}
}

// TestAssetDetection tests asset request detection
func TestAssetDetection(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/assets/app.js", true},
		{"/static/style.css", true},
		{"/favicon.ico", true},
		{"/api/users", false},
		{"/", false},
		{"/about", false},
	}

	for _, tt := range tests {
		result := isAssetRequest(tt.path)
		if result != tt.expected {
			t.Errorf("isAssetRequest(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

// TestAPIDetection tests API request detection
func TestAPIDetection(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/api/users", true},
		{"/v1/data", true},
		{"/health", true},
		{"/assets/app.js", false},
		{"/", false},
		{"/about", false},
	}

	for _, tt := range tests {
		result := isAPIRequest(tt.path)
		if result != tt.expected {
			t.Errorf("isAPIRequest(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

// TestHealthHandler tests the health endpoint
func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/__health__", nil)
	w := httptest.NewRecorder()
	
	healthHandler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}
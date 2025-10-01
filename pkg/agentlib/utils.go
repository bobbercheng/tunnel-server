package agentlib

import (
	"errors"
	"strings"
	"time"
)

// Error definitions
var (
	ErrUnauthorized   = errors.New("unauthorized: invalid ID or secret")
	ErrNetworkFailure = errors.New("network failure")
	ErrDNSFailure     = errors.New("DNS resolution failure")
	ErrTunnelMismatch = errors.New("tunnel protocol mismatch")
)

// maskSecretNew masks sensitive information for logging
func maskSecretNew(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// calculateBackoffNew calculates backoff duration based on error type
func calculateBackoffNew(err error, currentBackoff, maxBackoff time.Duration, multiplier float64) time.Duration {
	errorType := classifyNetworkErrorNew(err)

	switch errorType {
	case ErrUnauthorized:
		return 0 // Immediate retry after clearing credentials
	case ErrDNSFailure:
		return 5 * time.Second // Fixed delay for DNS issues
	case ErrTunnelMismatch:
		return 2 * time.Second // Quick retry for protocol mismatches
	default:
		// Exponential backoff for other errors
		next := time.Duration(float64(currentBackoff) * multiplier)
		if next > maxBackoff {
			return maxBackoff
		}
		return next
	}
}

// classifyNetworkErrorNew classifies network errors for appropriate handling
func classifyNetworkErrorNew(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for authentication errors
	if strings.Contains(errStr, "401") || strings.Contains(errStr, "unauthorized") {
		return ErrUnauthorized
	}

	// Check for DNS errors
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "dns") {
		return ErrDNSFailure
	}

	// Check for protocol mismatch
	if strings.Contains(errStr, "unsupported protocol scheme") {
		return ErrTunnelMismatch
	}

	return ErrNetworkFailure
}
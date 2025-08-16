package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Custom URL validation and management

var (
	// Reserved paths that cannot be used as custom URLs
	reservedPaths = map[string]bool{
		"__health__": true,
		"__pub__":    true,
		"__ws__":     true,
		"__tcp__":    true,
	}

	// Custom URL validation regex
	customURLRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$`)
)

// validateCustomURL validates a custom URL according to the rules
func validateCustomURL(customURL string) error {
	if customURL == "" {
		return nil // Empty custom URL is allowed
	}

	// Normalize: remove leading/trailing slashes
	normalized := strings.Trim(customURL, "/")
	
	// Check length (after removing slashes)
	if len(normalized) == 0 {
		return fmt.Errorf("custom URL cannot be empty after removing slashes")
	}
	if len(normalized) > 64 {
		return fmt.Errorf("custom URL too long (max 64 characters)")
	}

	// Check format using regex
	if !customURLRegex.MatchString(normalized) {
		return fmt.Errorf("custom URL format invalid (allowed: a-zA-Z0-9_- and /)")
	}

	// Check for reserved paths
	segments := strings.Split(normalized, "/")
	firstSegment := segments[0]
	
	if reservedPaths[firstSegment] {
		return fmt.Errorf("custom URL cannot start with reserved path: %s", firstSegment)
	}

	// Additional validation: no double slashes, no trailing/leading dots
	if strings.Contains(normalized, "//") {
		return fmt.Errorf("custom URL cannot contain double slashes")
	}
	if strings.HasPrefix(normalized, ".") || strings.HasSuffix(normalized, ".") {
		return fmt.Errorf("custom URL cannot start or end with dots")
	}
	for _, segment := range segments {
		if segment == "" {
			return fmt.Errorf("custom URL cannot have empty segments")
		}
		if strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, ".") {
			return fmt.Errorf("custom URL segments cannot start or end with dots")
		}
	}

	return nil
}

// isCustomURLAvailable checks if a custom URL is available (case-sensitive)
func isCustomURLAvailable(customURL string) bool {
	if customURL == "" {
		return true
	}

	normalized := strings.Trim(customURL, "/")
	
	customURLsMu.RLock()
	defer customURLsMu.RUnlock()
	
	_, exists := customURLs[normalized]
	return !exists
}

// getCustomURLStats returns statistics about custom URL usage
func getCustomURLStats() map[string]interface{} {
	customURLsMu.RLock()
	defer customURLsMu.RUnlock()

	stats := map[string]interface{}{
		"total_custom_urls": len(customURLs),
		"reserved_paths":    getReservedPathsList(),
	}

	// Analyze custom URL patterns
	patterns := map[string]int{
		"single_segment":    0, // e.g., "api"
		"two_segments":      0, // e.g., "api/v1"
		"three_or_more":     0, // e.g., "api/v1/users"
		"with_underscores":  0, // containing underscores
		"with_hyphens":      0, // containing hyphens
	}

	for customURL := range customURLs {
		segments := strings.Split(customURL, "/")
		segmentCount := len(segments)

		switch {
		case segmentCount == 1:
			patterns["single_segment"]++
		case segmentCount == 2:
			patterns["two_segments"]++
		default:
			patterns["three_or_more"]++
		}

		if strings.Contains(customURL, "_") {
			patterns["with_underscores"]++
		}
		if strings.Contains(customURL, "-") {
			patterns["with_hyphens"]++
		}
	}

	stats["url_patterns"] = patterns

	return stats
}

// getReservedPathsList returns the list of reserved paths
func getReservedPathsList() []string {
	paths := make([]string, 0, len(reservedPaths))
	for path := range reservedPaths {
		paths = append(paths, path)
	}
	return paths
}

// registerCustomURL registers a custom URL mapping (thread-safe)
func registerCustomURL(customURL, tunnelID string) error {
	if err := validateCustomURL(customURL); err != nil {
		return err
	}

	if customURL == "" {
		return nil // No custom URL to register
	}

	normalized := strings.Trim(customURL, "/")

	customURLsMu.Lock()
	defer customURLsMu.Unlock()

	// Check availability again under lock
	if _, exists := customURLs[normalized]; exists {
		return fmt.Errorf("custom URL already taken: %s", normalized)
	}

	customURLs[normalized] = tunnelID
	return nil
}

// unregisterCustomURL removes a custom URL mapping
func unregisterCustomURL(customURL string) {
	if customURL == "" {
		return
	}

	normalized := strings.Trim(customURL, "/")

	customURLsMu.Lock()
	defer customURLsMu.Unlock()

	delete(customURLs, normalized)
}

// findCustomURLByTunnelID finds custom URL(s) associated with a tunnel ID
func findCustomURLByTunnelID(tunnelID string) []string {
	customURLsMu.RLock()
	defer customURLsMu.RUnlock()

	var urls []string
	for customURL, tID := range customURLs {
		if tID == tunnelID {
			urls = append(urls, customURL)
		}
	}

	return urls
}

// cleanupCustomURLsForTunnel removes all custom URL mappings for a tunnel
func cleanupCustomURLsForTunnel(tunnelID string) {
	customURLsMu.Lock()
	defer customURLsMu.Unlock()

	var toDelete []string
	for customURL, tID := range customURLs {
		if tID == tunnelID {
			toDelete = append(toDelete, customURL)
		}
	}

	for _, customURL := range toDelete {
		delete(customURLs, customURL)
	}
}
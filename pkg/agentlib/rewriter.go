package agentlib

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// rewriteContent applies content rewriting rules to response bodies
func (a *Agent) rewriteContent(body []byte, contentType string, req *ReqFrame) []byte {
	// Only rewrite HTML, CSS, and JavaScript content
	if !a.shouldRewriteContent(contentType) {
		return body
	}

	// Ensure we have rewrite config loaded (fallback to defaults)
	if a.rewriteConfig == nil {
		a.rewriteConfig = a.getDefaultRewriteConfig()
	}

	content := string(body)
	originalSize := len(content)
	rewritten := content
	totalMatches := 0

	log.Printf("REWRITE: Processing content | ContentType: %s | Size: %d bytes | Rules: %d | ReqID: %s",
		contentType, originalSize, len(a.rewriteConfig.Rules), req.ReqID)

	// Apply each enabled rule that matches the content type
	for _, rule := range a.rewriteConfig.Rules {
		if !rule.Enabled || rule.compiledRegex == nil {
			continue
		}

		// Check if this rule applies to the current content type
		if !a.ruleMatchesContentType(rule, contentType) {
			continue
		}

		// Apply the rule
		matches := rule.compiledRegex.FindAllString(rewritten, -1)
		if len(matches) > 0 {
			rewritten = rule.compiledRegex.ReplaceAllString(rewritten, rule.Replacement)
			totalMatches += len(matches)
			log.Printf("REWRITE: Applied rule '%s' | Matches: %d | Patterns: %v | ReqID: %s",
				rule.Name, len(matches), matches, req.ReqID)
		}
	}

	rewrittenSize := len(rewritten)
	if totalMatches > 0 {
		log.Printf("REWRITE SUCCESS: Content modified | Original: %d bytes → Rewritten: %d bytes | Total matches: %d | ReqID: %s",
			originalSize, rewrittenSize, totalMatches, req.ReqID)
	} else {
		log.Printf("REWRITE: No rules matched | ContentType: %s | Size: %d bytes | ReqID: %s",
			contentType, originalSize, req.ReqID)
	}

	return []byte(rewritten)
}

// ruleMatchesContentType checks if a rewrite rule should be applied to the given content type
func (a *Agent) ruleMatchesContentType(rule RewriteRule, contentType string) bool {
	if len(rule.ContentTypes) == 0 {
		return true // No restrictions - apply to all content types
	}

	contentType = strings.ToLower(contentType)
	for _, ruleType := range rule.ContentTypes {
		if strings.Contains(contentType, strings.ToLower(ruleType)) {
			return true
		}
	}
	return false
}

// shouldRewriteContent determines if content should be rewritten based on Content-Type
func (a *Agent) shouldRewriteContent(contentType string) bool {
	contentType = strings.ToLower(contentType)

	rewriteTypes := []string{
		"text/html",
		"application/javascript",
		"text/javascript",
		"application/x-javascript",
		"text/css",
		"application/json",
		"text/plain", // Sometimes JavaScript is served as text/plain
		"text/x-json",
	}

	for _, t := range rewriteTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}
	return false
}

// rewriteResponseHeaders rewrites HTTP response headers to replace original domain references
func (a *Agent) rewriteResponseHeaders(headers http.Header, req *ReqFrame) {
	originalDomain := a.getOriginalDomain()
	tunnelDomain := a.getServerDomain()

	if originalDomain == "" || tunnelDomain == "" {
		return
	}

	headersModified := 0

	// CORS headers that need domain rewriting
	corsHeaders := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Methods",
		"Access-Control-Expose-Headers",
	}

	// Security headers that may reference domains
	securityHeaders := []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Referrer-Policy",
		"Permissions-Policy",
		"Feature-Policy",
	}

	// Location headers for redirects
	locationHeaders := []string{
		"Location",
		"Refresh",
	}

	// Process CORS headers
	for _, header := range corsHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value
				// Replace domain references in CORS headers
				newValue := strings.ReplaceAll(value, originalDomain, tunnelDomain)
				newValue = strings.ReplaceAll(newValue, "https://"+originalDomain, "https://"+tunnelDomain)
				newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain) // Force HTTPS

				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: CORS header %s | Original: %s | Rewritten: %s | ReqID: %s",
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Process security headers with more complex patterns
	for _, header := range securityHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value
				newValue := value

				// Handle Content-Security-Policy directives
				if header == "Content-Security-Policy" || header == "Content-Security-Policy-Report-Only" {
					// Replace domain in various CSP directives
					newValue = strings.ReplaceAll(newValue, "https://"+originalDomain, "https://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "wss://"+originalDomain, "wss://"+tunnelDomain)
					newValue = strings.ReplaceAll(newValue, "ws://"+originalDomain, "wss://"+tunnelDomain)
					// Handle wildcards and subdomains
					newValue = strings.ReplaceAll(newValue, "*."+originalDomain, "*."+tunnelDomain)
				} else {
					// For other security headers, do basic domain replacement
					newValue = strings.ReplaceAll(newValue, originalDomain, tunnelDomain)
				}

				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: Security header %s | Original: %s | Rewritten: %s | ReqID: %s",
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Process location headers for redirects
	for _, header := range locationHeaders {
		if values := headers[header]; len(values) > 0 {
			for i, value := range values {
				originalValue := value

				// Handle absolute URLs in location headers
				newValue := strings.ReplaceAll(value, "https://"+originalDomain, "https://"+tunnelDomain+a.getCustomURLPath())
				newValue = strings.ReplaceAll(newValue, "http://"+originalDomain, "https://"+tunnelDomain+a.getCustomURLPath())

				// Handle relative URLs that might become absolute
				if strings.HasPrefix(newValue, "/") && !strings.HasPrefix(newValue, "//") {
					newValue = "https://" + tunnelDomain + a.getCustomURLPath() + newValue
				}

				if newValue != originalValue {
					headers[header][i] = newValue
					headersModified++
					log.Printf("REWRITE: Location header %s | Original: %s | Rewritten: %s | ReqID: %s",
						header, originalValue, newValue, req.ReqID)
				}
			}
		}
	}

	// Handle Set-Cookie headers to update domain attributes
	if cookies := headers["Set-Cookie"]; len(cookies) > 0 {
		for i, cookie := range cookies {
			originalCookie := cookie

			// Replace domain attributes in cookies
			newCookie := strings.ReplaceAll(cookie, "Domain="+originalDomain, "Domain="+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "domain="+originalDomain, "domain="+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "Domain=."+originalDomain, "Domain=."+tunnelDomain)
			newCookie = strings.ReplaceAll(newCookie, "domain=."+originalDomain, "domain=."+tunnelDomain)

			if newCookie != originalCookie {
				headers["Set-Cookie"][i] = newCookie
				headersModified++
				log.Printf("REWRITE: Cookie header | Original: %s | Rewritten: %s | ReqID: %s",
					originalCookie, newCookie, req.ReqID)
			}
		}
	}

	if headersModified > 0 {
		log.Printf("REWRITE: Headers modified | Count: %d | ReqID: %s", headersModified, req.ReqID)
	}
}

// getOriginalDomain extracts domain from LocalURL (e.g., "chatgpt.com" from "https://chatgpt.com")
func (a *Agent) getOriginalDomain() string {
	if a.LocalURL == "" {
		return ""
	}

	// Parse the URL to extract hostname
	if u, err := url.Parse(a.LocalURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// getServerDomain returns the tunnel server domain (e.g., "connect.vexorium.net")
func (a *Agent) getServerDomain() string {
	if a.ServerURL == "" {
		return ""
	}

	if u, err := url.Parse(a.ServerURL); err == nil {
		return u.Hostname()
	}
	return ""
}

// getCustomURLPath returns the custom URL path (e.g., "/chatgpt-roundtripper-test")
func (a *Agent) getCustomURLPath() string {
	if a.CustomURL == "" {
		return ""
	}
	return "/" + a.CustomURL
}

// getTunnelBaseURL returns the full tunnel base URL
func (a *Agent) getTunnelBaseURL() string {
	serverDomain := a.getServerDomain()
	customPath := a.getCustomURLPath()

	if serverDomain == "" || customPath == "" {
		return ""
	}

	return "https://" + serverDomain + customPath
}

// rewriteJavaScriptAPICalls handles JavaScript fetch() and XMLHttpRequest rewriting
func (a *Agent) rewriteJavaScriptAPICalls(content, originalDomain, tunnelBase string) string {
	// Pattern for fetch() calls with absolute URLs
	// fetch("https://chatgpt.com/api/...") → fetch("/chatgpt-tunnel/api/...")

	// Simple regex-like replacements for common patterns
	patterns := []struct {
		old string
		new string
	}{
		// fetch() with double quotes
		{`fetch("https://` + originalDomain + `/`, `fetch("` + tunnelBase + `/`},
		{`fetch("https://` + originalDomain + `"`, `fetch("` + tunnelBase + `"`},
		// fetch() with single quotes
		{`fetch('https://` + originalDomain + `/`, `fetch('` + tunnelBase + `/`},
		{`fetch('https://` + originalDomain + `'`, `fetch('` + tunnelBase + `'`},
		// XMLHttpRequest.open()
		{`.open("GET", "https://` + originalDomain + `/`, `.open("GET", "` + tunnelBase + `/`},
		{`.open('GET', 'https://` + originalDomain + `/`, `.open('GET', '` + tunnelBase + `/`},
		// jQuery and axios
		{`$.get("https://` + originalDomain + `/`, `$.get("` + tunnelBase + `/`},
		{`axios.get("https://` + originalDomain + `/`, `axios.get("` + tunnelBase + `/`},
		// WebSocket connections
		{`new WebSocket("wss://` + originalDomain + `/`, `new WebSocket("wss://` + a.getServerDomain() + a.getCustomURLPath() + `/`},
	}

	result := content
	for _, p := range patterns {
		result = strings.ReplaceAll(result, p.old, p.new)
	}

	return result
}

// rewriteCSSURLs handles CSS url() and @import rewriting
func (a *Agent) rewriteCSSURLs(content, originalDomain, tunnelBase string) string {
	patterns := []struct {
		old string
		new string
	}{
		// CSS url() with various quote styles
		{`url("https://` + originalDomain + `/`, `url("` + tunnelBase + `/`},
		{`url('https://` + originalDomain + `/`, `url('` + tunnelBase + `/`},
		{`url(https://` + originalDomain + `/`, `url(` + tunnelBase + `/`},
		// @import statements
		{`@import "https://` + originalDomain + `/`, `@import "` + tunnelBase + `/`},
		{`@import 'https://` + originalDomain + `/`, `@import '` + tunnelBase + `/`},
		{`@import url("https://` + originalDomain + `/`, `@import url("` + tunnelBase + `/`},
	}

	result := content
	for _, p := range patterns {
		result = strings.ReplaceAll(result, p.old, p.new)
	}

	return result
}

// getDefaultRewriteConfig returns a default rewrite configuration
func (a *Agent) getDefaultRewriteConfig() *RewriteConfig {
	originalDomain := a.getOriginalDomain()
	if originalDomain == "" {
		originalDomain = "example.com" // fallback for generic rules
	}
	tunnelBase := "https://" + a.getServerDomain()

	rules := []RewriteRule{
		{
			Name:         "basic-url-replacement",
			Pattern:      fmt.Sprintf("https://%s", regexp.QuoteMeta(originalDomain)),
			Replacement:  tunnelBase,
			ContentTypes: []string{"text/html", "application/javascript", "text/css", "application/json"},
			Enabled:      true,
		},
		{
			Name:         "protocol-relative-urls",
			Pattern:      fmt.Sprintf("//%s", regexp.QuoteMeta(originalDomain)),
			Replacement:  "//" + a.getServerDomain(),
			ContentTypes: []string{"text/html", "application/javascript", "text/css"},
			Enabled:      true,
		},
		{
			Name:         "javascript-variable-assignment",
			Pattern:      fmt.Sprintf(`(const|let|var)\s+(\w+)\s*=\s*["']https://%s(/[^"']*)?["']`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`$1 $2 = "%s$3"`, tunnelBase),
			ContentTypes: []string{"application/javascript", "text/html"},
			Enabled:      true,
		},
		{
			Name:         "json-property-urls",
			Pattern:      fmt.Sprintf(`"([^"]*)":\s*"https://%s(/[^"]*)?`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`"$1": "%s$2"`, tunnelBase),
			ContentTypes: []string{"application/json", "application/javascript"},
			Enabled:      true,
		},
		{
			Name:         "css-url-function",
			Pattern:      fmt.Sprintf(`url\s*\(\s*["']?https://%s(/[^"'\)]*)?["']?\s*\)`, regexp.QuoteMeta(originalDomain)),
			Replacement:  fmt.Sprintf(`url("%s$1")`, tunnelBase),
			ContentTypes: []string{"text/css", "text/html"},
			Enabled:      true,
		},
	}

	// Compile all default patterns
	for i := range rules {
		rule := &rules[i]
		if rule.Enabled && rule.Pattern != "" {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				log.Printf("REWRITE CONFIG: Warning - failed to compile default pattern '%s': %v", rule.Pattern, err)
				rule.Enabled = false
				continue
			}
			rule.compiledRegex = compiled
		}
	}

	return &RewriteConfig{Rules: rules}
}
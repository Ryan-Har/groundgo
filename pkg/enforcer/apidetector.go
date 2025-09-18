package enforcer

import (
	"net/http"
	"strings"
)

// APIRequestDetector is a function type that determines if a request is an API request
type APIRequestDetector func(*http.Request) bool

// WithAPIDetector allows users to provide their own API detection logic
func (e *Enforcer) WithAPIDetector(detector APIRequestDetector) *Enforcer {
	e.APIDetector = detector
	return e
}

// defaultAPIDetector provides a simple, reliable default implementation
func defaultAPIDetector(r *http.Request) bool {
	// Check Accept header - most reliable indicator
	acceptHeader := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(acceptHeader, "application/json") {
		return true
	}

	// Check Content-Type for requests with body
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		return true
	}

	// Fallback: check for common API path patterns
	path := strings.ToLower(r.URL.Path)
	return strings.HasPrefix(path, "/api/") ||
		strings.HasPrefix(path, "/v1/") ||
		strings.HasPrefix(path, "/v2/")
}

// PathOnlyDetector - simple path-based detection
func PathOnlyDetector(r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	return strings.HasPrefix(path, "/api/")
}

// HeaderOnlyDetector - only looks at content negotiation
func HeaderOnlyDetector(r *http.Request) bool {
	acceptHeader := strings.ToLower(r.Header.Get("Accept"))
	contentType := strings.ToLower(r.Header.Get("Content-Type"))

	return strings.Contains(acceptHeader, "application/json") ||
		strings.Contains(contentType, "application/json")
}

// AlwaysAPIDetector - treats everything as API (useful for API-only services)
func AlwaysAPIDetector(r *http.Request) bool {
	return true
}

// NeverAPIDetector - treats everything as web (useful for web-only services)
func NeverAPIDetector(r *http.Request) bool {
	return false
}

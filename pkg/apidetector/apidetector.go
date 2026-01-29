package apidetector

import (
	"net/http"
	"strings"
)

// APIRequestDetector is a function type that determines if a request is an API request
type APIRequestDetector func(*http.Request) bool

// Default provides a simple, reliable default implementation
func Default(r *http.Request) bool {
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

// PathOnly - simple path-based detection
func PathOnly(r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	return strings.HasPrefix(path, "/api/")
}

// HeaderOnlyDetector - only looks at content negotiation
func HeaderOnly(r *http.Request) bool {
	acceptHeader := strings.ToLower(r.Header.Get("Accept"))
	contentType := strings.ToLower(r.Header.Get("Content-Type"))

	return strings.Contains(acceptHeader, "application/json") ||
		strings.Contains(contentType, "application/json")
}

// AlwaysAPIDetector - treats everything as API (useful for API-only services)
func Always(r *http.Request) bool {
	return true
}

// NeverAPIDetector - treats everything as web (useful for web-only services)
func Never(r *http.Request) bool {
	return false
}

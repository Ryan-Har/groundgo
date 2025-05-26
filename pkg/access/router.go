package access

import (
	"errors"
	"net/http"
	"strings"
)

// Router defines an abstraction for registering routes and applying middleware.
// It allows Enforcer to remain decoupled from specific HTTP frameworks.
type Router interface {
	Handle(pattern string, handler http.Handler)
}

// Handle registers an HTTP handler with the router for the given route pattern.
// The route string can be either:
//
//	"/path"          // matches all HTTP methods for /path
//	"METHOD /path"   // matches only HTTP requests with METHOD (GET, POST, etc.)
//
// If the method is omitted, it defaults to all methods.
// The handler is automatically wrapped with authentication and authorization middlewares
// based on policies previously set with SetPolicy.
func (e *Enforcer) Handle(route string, handler http.Handler) {
	e.logger.V(1).Info("enforcer handling route", "route", route)
	method, path := parseRoute(route)

	// Initialize handler map if not already
	if e.handlers == nil {
		e.handlers = make(map[string]map[string]http.Handler)
	}

	// Initialize method map for the path if not already
	if _, exists := e.handlers[path]; !exists {
		e.handlers[path] = make(map[string]http.Handler)

		// Register the dispatching handler once
		e.router.Handle(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.logger.V(3).Info("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
			methodHandlers := e.handlers[path]

			// Try exact method match first
			if h, ok := methodHandlers[r.Method]; ok {
				h.ServeHTTP(w, r)
				return
			}

			// Try wildcard (no method specified during registration)
			if h, ok := methodHandlers[""]; ok {
				h.ServeHTTP(w, r)
				return
			}

			// Otherwise: method not allowed
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}))
	}

	// Check for duplicate route
	if _, exists := e.handlers[path][method]; exists {
		err := errors.New("enforcer: duplicate route attempted")
		e.logger.Error(err, "ERROR", "path", path, "method", method)
	}

	// Apply auth/authz middleware
	wrapped := e.WrapHandler(path, method, handler)

	// Store handler
	e.handlers[path][method] = wrapped
}

// HandleFunc is a convenience wrapper around Handle that accepts
// an http.HandlerFunc instead of a full http.Handler.
// It registers the handler function with authentication and authorization
// middlewares applied according to Enforcer policies.
func (e *Enforcer) HandleFunc(route string, handlerFunc http.HandlerFunc) {
	e.Handle(route, handlerFunc)
}

// parseRoute parses a route string into method and path components.
// Valid formats are:
//
//	"METHOD /path"   e.g. "GET /admin"
//	"/path"          e.g. "/admin"
//
// If the method is omitted, the returned method string is empty,
// meaning the route applies to all HTTP methods.
func parseRoute(route string) (method, path string) {
	parts := strings.Fields(route)
	switch len(parts) {
	case 0:
		return "", "/" // fallback to root
	case 1:
		return "", parts[0] // any method
	default:
		return strings.ToUpper(parts[0]), parts[1] // e.g. GET /admin
	}
}

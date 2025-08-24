package enforcer

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Ryan-Har/groundgo/internal/logutil"
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
// If the path is omitted, it defaults to the root path with the provided method
// If the combination of Method and path is already set, an error will be returned
// The handler is automatically dynamically wrapped with authentication and
// authorization middlewares based on policies set with SetPolicy.
func (e *Enforcer) Handle(route string, handler http.Handler) error {
	e.log.Debug("enforcer handling route", "route", route)
	if handler == nil {
		err := fmt.Errorf("cannot register nil handler for route")
		e.log.Error("cannot register nil handler for route", "route", route)
		return err
	}

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
			defer logutil.NewTimingLogger(e.log, time.Now(), "access handled", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())()
			methodHandlers := e.handlers[path]

			// Try exact method match first
			if h, ok := methodHandlers[r.Method]; ok {
				wrapped := e.WrapHandler(path, r.Method, h)
				wrapped.ServeHTTP(w, r)
				return
			}

			// Try wildcard (no method specified during registration)
			if h, ok := methodHandlers[""]; ok {
				wrapped := e.WrapHandler(path, r.Method, h)
				wrapped.ServeHTTP(w, r)
				return
			}

			// Otherwise: method not allowed
			e.respondMethodNotAllowed(w, r)
		}))
	}

	// Check for duplicate route
	if _, exists := e.handlers[path][method]; exists {
		return logutil.LogAndWrapErr(e.log, "attempted to add duplicate path to enforcer",
			NewDuplicatePathAndMethodError(path, method))
	}

	// Store handler
	e.handlers[path][method] = handler
	return nil
}

// HandleFunc is a convenience wrapper around Handle that accepts
// an http.HandlerFunc instead of a full http.Handler.
// It registers the handler function with authentication and authorization
// middlewares applied according to Enforcer policies.
func (e *Enforcer) HandleFunc(route string, handlerFunc http.HandlerFunc) error {
	return e.Handle(route, handlerFunc)
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
		// If it starts with "/" treat as path, otherwise treat as invalid
		if strings.HasPrefix(parts[0], "/") {
			return "", parts[0] // any method
		}
		// method but no path
		return "", "/"
	default:
		return strings.ToUpper(parts[0]), strings.ToLower(parts[1]) // e.g. GET /admin
	}
}

var ErrDuplicatePathAndMethod = &DuplicatePathAndMethodError{}

// errors
type DuplicatePathAndMethodError struct {
	Method string
	Path   string
}

func NewDuplicatePathAndMethodError(path, method string) *DuplicatePathAndMethodError {
	return &DuplicatePathAndMethodError{
		Method: method,
		Path:   path,
	}
}

func (e *DuplicatePathAndMethodError) Error() string {
	return fmt.Sprintf("enforcer: duplicate path: %s and method: %s attempted", e.Path, e.Method)
}

func (e *DuplicatePathAndMethodError) Is(target error) bool {
	_, ok := target.(*DuplicatePathAndMethodError)
	return ok
}

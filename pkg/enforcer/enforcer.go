package enforcer

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

// Enforcer manages access control policies and wraps route handlers with
// authentication and authorization logic. It is typically used to guard routes
// based on roles defined in the Policies map.
type Enforcer struct {
	log      *slog.Logger
	Policies map[string]map[string]models.Role  // e.g route: {Get: RoleUser, Post: RoleAdmin}
	handlers map[string]map[string]http.Handler // path -> method -> handler internal mapping
	router   Router                             // used for middlewares and creating routes
	auth     AuthStore
	session  SessionStore
	token    TokenStore
	Config
	mu sync.RWMutex // mutex to protect policies and handlers maps
}

type Config struct {
	GuestCookieName         string // string used for the session cookie of guest user
	GuestCookieSecure       bool   // determines if the cookie should be secure or not. Recommended always to be true in production environments
	GuestCookiePath         string // path set for the session cookie of the guest user
	RedirectOnAuthErrorPath string // path of the redirection location when authentication fails
}

// AuthStore defines the subset of authentication methods
// that the Enforcer requires to fetch user information during
// token/session validation and access control.
type AuthStore interface {
	// GetUserByID retrieves a user by their unique identifier.
	// Returns (nil, nil) if the user does not exist.
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
}

// SessionStore defines the minimal session-related functionality
// that Enforcer uses for session validation and management in requests.
type SessionStore interface {
	// Create generates and stores a new session, returning the new session model.
	Create(ctx context.Context, userID uuid.UUID) (*models.Session, error)

	// Get retrieves the session by its ID.
	// Should return an error or (nil, nil) if the session is expired or not found.
	Get(ctx context.Context, sessionID string) (*models.Session, error)

	// ExpireCookie clears a session cookie on the client by writing
	// an expired cookie to the response. Used during logout and invalidation flows.
	ExpireCookie(c *http.Cookie, w http.ResponseWriter)
}

// TokenStore defines the token parsing and revocation-checking
// capabilities required by Enforcer for JWT-based authentication.
type TokenStore interface {
	// ParseAccessTokenAndValidate is a helper that both Parses Access Token
	// And Checks if the token is revoked, providing an error if it is not a valid token
	ParseAccessTokenAndValidate(ctx context.Context, tokenStr string) (*tokenstore.AccessToken, error)
}

// NewEnforcer initializes and returns a new Enforcer instance.
//
// The Enforcer manages route access policies and wraps HTTP handlers
// with authentication and authorization logic. It maintains a mapping of
// allowed roles per HTTP method and path, and handles enforcement
// through middleware integration with the provided router.
//
// Params:
//   - logger: a logr.Logger for structured logging
//   - router: an implementation of the Router interface used to register and manage routes
//   - auth: an authentication store used to validate user credentials
//   - sess: a session store used to persist user sessions
//
// The Enforcer initializes with:
//   - An empty Policies map: policies can be added dynamically to control route access
//   - Internal handler mapping used to wrap and manage protected routes
//
// Example:
//
//	enforcer := NewEnforcer(logger, router, authStore, sessionStore, tokenstore, config)
func NewEnforcer(logger *slog.Logger, router Router, auth AuthStore, sess SessionStore, token TokenStore, config *Config) *Enforcer {
	if config == nil {
		config = newDefaultConfig()
	}

	return &Enforcer{
		log:      logger,
		Policies: make(map[string]map[string]models.Role),
		handlers: make(map[string]map[string]http.Handler),
		router:   router,
		auth:     auth,
		session:  sess,
		token:    token,
		Config:   *config,
	}
}

// new default config returns a pointer to Config with the default options
func newDefaultConfig() *Config {
	return &Config{
		GuestCookieName:         "session_token",
		GuestCookiePath:         "/",
		GuestCookieSecure:       true,
		RedirectOnAuthErrorPath: "/login",
	}
}

// SetPolicy allows defining the minimum required role for a given resource path and HTTP method.
// Use "*" as the method to apply the policy to all methods for that path.
func (e *Enforcer) SetPolicy(resourcePath string, method string, requiredRole models.Role) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !strings.HasPrefix(resourcePath, "/") {
		resourcePath = "/" + resourcePath
	}
	if _, ok := e.Policies[resourcePath]; !ok {
		e.Policies[resourcePath] = make(map[string]models.Role)
	}
	e.Policies[resourcePath][strings.ToUpper(method)] = requiredRole // Store method in uppercase
}

// FindMatchingPolicy finds the most specific policy for a given resource path and method.
// It prioritizes exact method matches over wildcard method matches.
func (e *Enforcer) FindMatchingPolicy(resourcePath, method string) (models.Role, bool) {
	method = strings.ToUpper(method)

	// Build all prefixes from most specific to least
	pathsToCheck := buildPrefixes(resourcePath)

	e.log.Debug("enforcer is finding matching policy",
		"resource path", resourcePath,
		"method", method,
		"paths to check", pathsToCheck,
	)

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, p := range pathsToCheck {
		if methodPolicies, ok := e.Policies[p]; ok {

			// 1. Exact method match
			if requiredRole, methodOk := methodPolicies[method]; methodOk {
				e.log.Debug("enforcer matched policy for path", "path", p, "available_methods", methodPolicies)
				return requiredRole, true
			}

			// 2. Wildcard match
			if requiredRole, anyMethodOk := methodPolicies["*"]; anyMethodOk {
				e.log.Debug("enforcer matched wildcard policy for path", "path", p, "available_methods", methodPolicies)
				return requiredRole, true
			}
		}
	}

	// No match
	return models.RoleGuest, false
}

// buildPrefixes returns a list of paths to check from most specific to least specific.
// For "/a/b/c" it returns ["/a/b/c", "/a/b", "/a", "/"].
// Preserves the exact path format as specified in HTTP routes.
func buildPrefixes(path string) []string {
	// Handle empty path or root path
	if path == "" || path == "/" {
		return []string{"/"}
	}

	// Split path into segments, removing empty segments from splitting
	segments := strings.Split(strings.Trim(path, "/"), "/")

	// Handle the case where path was just "/" (segments would be [""])
	if len(segments) == 1 && segments[0] == "" {
		return []string{"/"}
	}

	prefixes := make([]string, 0, len(segments)+1)

	// Build prefixes from most specific to least specific
	for i := len(segments); i > 0; i-- {
		if i == 1 {
			// For single segment, just add leading slash
			prefixes = append(prefixes, "/"+segments[0])
		} else {
			// For multiple segments, join with slashes
			prefixes = append(prefixes, "/"+strings.Join(segments[:i], "/"))
		}
	}

	// Always ensure root "/" is last
	prefixes = append(prefixes, "/")

	return prefixes
}

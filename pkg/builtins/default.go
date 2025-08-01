package builtins

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/store"
)

type Builtin struct {
	enforcer *enforcer.Enforcer
	handler  Handler
}

// New initializes and returns a new DefaultRoutes instance
func New(logger *slog.Logger, enforcer *enforcer.Enforcer, auth store.Authstore, session store.Sessionstore, token store.Tokenstore) *Builtin {
	return &Builtin{
		enforcer: enforcer,
		handler:  *newHandler(logger, auth, session, token),
	}
}

// LoadAll loads all default route groups (login, signup, admin, etc.).
// If any group fails to register its routes, the error(s) will be combined
// and returned as a single error via errors.Join.
func (b *Builtin) LoadAllRoutes() error {
	errs := []error{
		b.LoadDefaultLoginRoute(),
		b.LoadDefaultSignupRoute(),
		b.LoadDefaultAdminRoute(),
		b.LoadDefaultAPIRoutes(),
	}

	return errors.Join(errs...)
}

func (b *Builtin) LoadAllPolicies() {
	b.enforcer.SetPolicy("/login", "GET", models.RoleGuest)
	b.enforcer.SetPolicy("/login", "POST", models.RoleGuest)
	b.enforcer.SetPolicy("/signup", "GET", models.RoleGuest)
	b.enforcer.SetPolicy("/signup", "POST", models.RoleGuest)
	b.enforcer.SetPolicy("/", "GET", models.RoleGuest)
}

// SetDefaultLoginRoute configures the HTTP handlers for the user login process.
//
// It defines two handlers: one for serving the login page on a GET request
// and another for processing the login form submission on a POST request.
// The POST handler validates credentials, creates a user session, and sets a
// session cookie upon successful authentication.
func (b *Builtin) LoadDefaultLoginRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET /login":  b.handler.handleLoginGet(),
		"POST /login": b.handler.handleLoginPost(),
	})
}

// SetDefaultSignupRoute configures the HTTP handlers for the new user
// registration process.
//
// It defines two handlers: one for serving the signup page on a GET request
// and another for processing the new user form on a POST request. The POST
// handler validates the submitted data, checks for existing users, creates a
// new user account, and initiates a session.
func (b *Builtin) LoadDefaultSignupRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET /signup":  b.handler.handleSignupGet(),
		"POST /signup": b.handler.handleSignupPost(),
	})
}

// SetDefaultAdminRoute configures the HTTP handler for the admin dashboarb.
//
// It defines multiple handlers for the various htmx interactive components.
func (b *Builtin) LoadDefaultAdminRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET /admin":                     b.handler.handleAdminGet(),
		"GET /admin/users/{id}":          b.handler.handleAdminUserRowGet(),
		"GET /admin/users/{id}/edit-row": b.handler.handleAdminUserRowEditGet(),
		"PUT /admin/users/{id}/claims":   b.handler.handleAdminUserClaimsPut(),
		"DELETE /admin/users/{id}":       b.handler.handleAdminUserDelete(),
		"POST /admin/users/{id}/disable": b.handler.handleAdminUserDisable(),
		"POST /admin/users/{id}/enable":  b.handler.handleAdminUserEnable(),
	})
}

func (b *Builtin) LoadDefaultAPIRoutes() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET /api/v1/token/verify":  b.handler.handleAPITokenVerify(),
		"GET /api/v1/token/refresh": b.handler.handleAPITokenRefresh(),
		"POST /api/v1/login":        b.handler.handleAPILoginPost(),
	})
}

// registerRoutes registers a set of HTTP routes with their corresponding handlers.
// It accepts a map where the keys are route patterns (e.g., "GET /login")
// and the values are the associated http.HandlerFunc implementations.
//
// If any calls to enforcer.Handle fail, all resulting errors are collected
// and returned as a single error using errors.Join. If all registrations succeed,
// the returned error will be nil.
//
// Example:
//
//	err := b.registerRoutes(map[string]http.HandlerFunc{
//	    "GET /login":  b.handleLoginGet(),
//	    "POST /login": b.handleLoginPost(),
//	})
func (b *Builtin) registerRoutes(routes map[string]http.HandlerFunc) error {
	var errs []error
	for pattern, handler := range routes {
		if err := b.enforcer.Handle(pattern, handler); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

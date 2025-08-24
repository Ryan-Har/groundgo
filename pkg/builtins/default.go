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
		handler:  *newHandler(logger, auth, session, token, "", "/groundgo/api/v1"),
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
	b.LoadDefaultRootPolicy()
	b.LoadDefaultLoginPolicies()
	b.LoadDefaultSignupPolicies()
	b.LoadDefaultAPIPolicies()
	b.LoadDefaultAdminPolicies()
}

func (b *Builtin) LoadDefaultRootPolicy() {
	b.enforcer.SetPolicy(b.handler.baseRoute+"/", "GET", models.RoleGuest)
}

// SetDefaultLoginRoute configures the HTTP handlers for the user login process.
//
// It defines two handlers: one for serving the login page on a GET request
// and another for processing the login form submission on a POST request.
// The POST handler validates credentials, creates a user session, and sets a
// session cookie upon successful authentication.
func (b *Builtin) LoadDefaultLoginRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET " + b.handler.baseRoute + "/login":  b.handler.handleLoginGet(),
		"POST " + b.handler.baseRoute + "/login": b.handler.handleLoginPost(),
	})
}

func (b *Builtin) LoadDefaultLoginPolicies() {
	b.enforcer.SetPolicy(b.handler.baseRoute+"/login", "GET", models.RoleGuest)
	b.enforcer.SetPolicy(b.handler.baseRoute+"/login", "POST", models.RoleGuest)
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
		"GET " + b.handler.baseRoute + "/signup":  b.handler.handleSignupGet(),
		"POST " + b.handler.baseRoute + "/signup": b.handler.handleSignupPost(),
	})
}

func (b *Builtin) LoadDefaultSignupPolicies() {
	b.enforcer.SetPolicy(b.handler.baseRoute+"/signup", "GET", models.RoleGuest)
	b.enforcer.SetPolicy(b.handler.baseRoute+"/signup", "POST", models.RoleGuest)
}

// SetDefaultAdminRoute configures the HTTP handler for the admin dashboarb.
//
// It defines multiple handlers for the various htmx interactive components.
func (b *Builtin) LoadDefaultAdminRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET " + b.handler.baseRoute + "/admin":                     b.handler.handleAdminGet(),
		"GET " + b.handler.baseRoute + "/admin/users/{id}":          b.handler.handleAdminUserRowGet(),
		"GET " + b.handler.baseRoute + "/admin/users/{id}/edit-row": b.handler.handleAdminUserRowEditGet(),
		"PUT " + b.handler.baseRoute + "/admin/users/{id}":          b.handler.handleAdminUserUpdatePut(),
		"DELETE " + b.handler.baseRoute + "/admin/users/{id}":       b.handler.handleAdminUserDelete(),
		"POST " + b.handler.baseRoute + "/admin/users/{id}/disable": b.handler.handleAdminUserDisable(),
		"POST " + b.handler.baseRoute + "/admin/users/{id}/enable":  b.handler.handleAdminUserEnable(),
	})
}

func (b *Builtin) LoadDefaultAdminPolicies() {
	b.enforcer.SetPolicy("/admin", "*", models.RoleAdmin)
}

func (b *Builtin) LoadDefaultAPIRoutes() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		// auth
		"POST " + b.handler.apiBaseRoute + "/auth/login":   b.handler.handleAPILoginPost(),
		"POST " + b.handler.apiBaseRoute + "/auth/logout":  b.handler.handleAPILogoutPost(),
		"POST " + b.handler.apiBaseRoute + "/auth/refresh": b.handler.handleAPITokenRefresh(),
		"GET " + b.handler.apiBaseRoute + "/auth/verify":   b.handler.handleAPITokenVerify(),
		// users
		"GET " + b.handler.apiBaseRoute + "/users":         b.handler.handleAPIGetUsers(),
		"POST " + b.handler.apiBaseRoute + "/users":        b.handler.handleAPICreateUser(),
		"GET " + b.handler.apiBaseRoute + "/users/{id}":    b.handler.handleAPIGetUserByID(),
		"PATCH " + b.handler.apiBaseRoute + "/users/{id}":  b.handler.handleAPIUpdateUserByID(),
		"DELETE " + b.handler.apiBaseRoute + "/users/{id}": b.handler.handleAPIDeleteUserByID(),
		//self
		"GET " + b.handler.apiBaseRoute + "/users/me":                  b.handler.handleAPIGetOwnUser(),
		"POST " + b.handler.apiBaseRoute + "/users/me/change-password": b.handler.HandleAPIChangeOwnPassword(),
	})
}

func (b *Builtin) LoadDefaultAPIPolicies() {
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/auth/login", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/auth/logout", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/auth/refresh", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/auth/verify", "GET", models.RoleUser)

	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users", "GET", models.RoleAdmin)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users", "POST", models.RoleAdmin)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users/{id}", "GET", models.RoleAdmin)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users/{id}", "PATCH", models.RoleAdmin)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users/{id}", "DELETE", models.RoleSystemAdmin)

	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users/me", "GET", models.RoleUser)
	b.enforcer.SetPolicy(b.handler.apiBaseRoute+"/users/me/change-password", "POST", models.RoleUser)
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

package builtins

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/Ryan-Har/groundgo/api"
	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/store"
	"github.com/Ryan-Har/groundgo/web"
)

type Builtin struct {
	enforcer     *enforcer.Enforcer
	webhandler   *web.Handler
	apihandler   *api.Handler
	baseRoute    string
	apiBaseRoute string
}

// New initializes and returns a new DefaultRoutes instance
func New(logger *slog.Logger,
	enforcer *enforcer.Enforcer,
	auth store.Authstore,
	session store.Sessionstore,
	token store.Tokenstore,
	cookie store.Cookiestore) *Builtin {
	return &Builtin{
		enforcer:     enforcer,
		webhandler:   web.New(logger, auth, session, cookie),
		apihandler:   api.New(logger, auth, session, token, cookie),
		baseRoute:    "",
		apiBaseRoute: "/groundgo/api/v1",
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
	b.enforcer.SetPolicy(b.baseRoute+"/", "GET", models.RoleGuest)
}

// SetDefaultLoginRoute configures the HTTP handlers for the user login process.
//
// It defines two handlers: one for serving the login page on a GET request
// and another for processing the login form submission on a POST request.
// The POST handler validates credentials, creates a user session, and sets a
// session cookie upon successful authentication.
func (b *Builtin) LoadDefaultLoginRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET " + b.baseRoute + "/login":  b.webhandler.HandleLoginGet(),
		"POST " + b.baseRoute + "/login": b.webhandler.HandleLoginPost(),
	})
}

func (b *Builtin) LoadDefaultLoginPolicies() {
	b.enforcer.SetPolicy(b.baseRoute+"/login", "GET", models.RoleGuest)
	b.enforcer.SetPolicy(b.baseRoute+"/login", "POST", models.RoleGuest)
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
		"GET " + b.baseRoute + "/signup":  b.webhandler.HandleSignupGet(),
		"POST " + b.baseRoute + "/signup": b.webhandler.HandleSignupPost(),
	})
}

func (b *Builtin) LoadDefaultSignupPolicies() {
	b.enforcer.SetPolicy(b.baseRoute+"/signup", "GET", models.RoleGuest)
	b.enforcer.SetPolicy(b.baseRoute+"/signup", "POST", models.RoleGuest)
}

// SetDefaultAdminRoute configures the HTTP handler for the admin dashboarb.
//
// It defines multiple handlers for the various htmx interactive components.
func (b *Builtin) LoadDefaultAdminRoute() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		"GET " + b.baseRoute + "/admin":                     b.webhandler.HandleAdminGet(),
		"GET " + b.baseRoute + "/admin/users/{id}":          b.webhandler.HandleAdminUserRowGet(),
		"GET " + b.baseRoute + "/admin/users/{id}/edit-row": b.webhandler.HandleAdminUserRowEditGet(),
		"PUT " + b.baseRoute + "/admin/users/{id}":          b.webhandler.HandleAdminUserUpdatePut(),
		"DELETE " + b.baseRoute + "/admin/users/{id}":       b.webhandler.HandleAdminUserDelete(),
		"POST " + b.baseRoute + "/admin/users/{id}/disable": b.webhandler.HandleAdminUserDisable(),
		"POST " + b.baseRoute + "/admin/users/{id}/enable":  b.webhandler.HandleAdminUserEnable(),
	})
}

func (b *Builtin) LoadDefaultAdminPolicies() {
	b.enforcer.SetPolicy("/admin", "*", models.RoleAdmin)
}

func (b *Builtin) LoadDefaultAPIRoutes() error {
	return b.registerRoutes(map[string]http.HandlerFunc{
		// auth
		"POST " + b.apiBaseRoute + "/auth/login":   b.apihandler.HandleAPILoginPost(),
		"POST " + b.apiBaseRoute + "/auth/logout":  b.apihandler.HandleAPILogoutPost(),
		"POST " + b.apiBaseRoute + "/auth/refresh": b.apihandler.HandleAPITokenRefresh(),
		"GET " + b.apiBaseRoute + "/auth/verify":   b.apihandler.HandleAPITokenVerify(),
		// users
		"GET " + b.apiBaseRoute + "/users":         b.apihandler.HandleAPIGetUsers(),
		"POST " + b.apiBaseRoute + "/users":        b.apihandler.HandleAPICreateUser(),
		"GET " + b.apiBaseRoute + "/users/{id}":    b.apihandler.HandleAPIGetUserByID(),
		"PATCH " + b.apiBaseRoute + "/users/{id}":  b.apihandler.HandleAPIUpdateUserByID(),
		"DELETE " + b.apiBaseRoute + "/users/{id}": b.apihandler.HandleAPIDeleteUserByID(),
		//self
		"GET " + b.apiBaseRoute + "/users/me":                  b.apihandler.HandleAPIGetOwnUser(),
		"POST " + b.apiBaseRoute + "/users/me/change-password": b.apihandler.HandleAPIChangeOwnPassword(),
	})
}

func (b *Builtin) LoadDefaultAPIPolicies() {
	b.enforcer.SetPolicy(b.apiBaseRoute+"/auth/login", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/auth/logout", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/auth/refresh", "POST", models.RoleGuest)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/auth/verify", "GET", models.RoleUser)

	b.enforcer.SetPolicy(b.apiBaseRoute+"/users", "GET", models.RoleAdmin)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/users", "POST", models.RoleAdmin)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/users/{id}", "GET", models.RoleAdmin)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/users/{id}", "PATCH", models.RoleAdmin)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/users/{id}", "DELETE", models.RoleSystemAdmin)

	b.enforcer.SetPolicy(b.apiBaseRoute+"/users/me", "GET", models.RoleUser)
	b.enforcer.SetPolicy(b.apiBaseRoute+"/users/me/change-password", "POST", models.RoleUser)
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

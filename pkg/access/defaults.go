package access

import (
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/Ryan-Har/groundgo/web/templates"
)

// LoadDefaultPolicies sets a baseline set of access control rules for common
// public routes like login, signup, and the home page.
//
// These policies grant access to unauthenticated (guest) users and are
// typically called during application startup before any custom policies
// are added.
func (e *Enforcer) LoadDefaultPolicies() {
	e.SetPolicy("/login", "GET", models.RoleGuest)
	e.SetPolicy("/login", "POST", models.RoleGuest)
	e.SetPolicy("/signup", "GET", models.RoleGuest)
	e.SetPolicy("/signup", "POST", models.RoleGuest)
	e.SetPolicy("/", "GET", models.RoleGuest)
}

// LoadDefaultRoutes registers the default web routes for core functionalities.
//
// It acts as a convenience method to call SetDefaultLoginRoute,
// SetDefaultSignupRoute, and SetDefaultAdminRoute, ensuring that all
// standard endpoints are configured with a single call during application setup.
func (e *Enforcer) LoadDefaultRoutes() {
	e.SetDefaultLoginRoute()
	e.SetDefaultSignupRoute()
	e.SetDefaultAdminRoute()
}

// SetDefaultLoginRoute configures the HTTP handlers for the user login process.
//
// It defines two handlers: one for serving the login page on a GET request
// and another for processing the login form submission on a POST request.
// The POST handler validates credentials, creates a user session, and sets a
// session cookie upon successful authentication.
func (e *Enforcer) SetDefaultLoginRoute() {
	e.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		content := templates.LoginPage()
		if err := templates.Layout("Login", content).Render(r.Context(), w); err != nil {
			e.logger.Error(err, "unable to GET /login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	e.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		defer e.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			e.logger.Error(err, "parsing form from POST /login")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		e.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := e.auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				e.logger.Error(err, "returning login error from POST /login")
			}
			return
		}
		if !passwd.Authenticate(password, *user.PasswordHash) {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				e.logger.Error(err, "returning login error from POST /login")
			}
			return
		}

		session, err := e.session.Create(r.Context(), user.ID)
		if err != nil {
			e.logger.Error(err, "creating session")
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})
}

// SetDefaultSignupRoute configures the HTTP handlers for the new user
// registration process.
//
// It defines two handlers: one for serving the signup page on a GET request
// and another for processing the new user form on a POST request. The POST
// handler validates the submitted data, checks for existing users, creates a
// new user account, and initiates a session.
func (e *Enforcer) SetDefaultSignupRoute() {
	e.HandleFunc("GET /signup", func(w http.ResponseWriter, r *http.Request) {
		content := templates.SignupPage()
		if err := templates.Layout("Signup", content).Render(r.Context(), w); err != nil {
			e.logger.Error(err, "unable to GET /signup")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	e.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		defer e.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			e.logger.Error(err, "parsing form from POST /signup")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		e.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			if err := templates.SignupError("Passwords do not match").Render(r.Context(), w); err != nil {
				e.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		if exists, _ := e.auth.CheckEmailExists(r.Context(), email); exists {
			if err := templates.SignupError("Account already exists").Render(r.Context(), w); err != nil {
				e.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		user, err := e.auth.CreateUser(r.Context(), models.CreateUserParams{
			Email:    email,
			Password: &password,
			Role:     "user",
			Claims:   models.Claims{},
		})
		if err != nil {
			if err := templates.SignupError("Unable to create user, please try again later.").Render(r.Context(), w); err != nil {
				e.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		session, err := e.session.Create(r.Context(), user.ID)
		if err != nil {
			e.logger.Error(err, "creating session")
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})
}

// SetDefaultAdminRoute configures the HTTP handler for the admin dashboard.
func (e *Enforcer) SetDefaultAdminRoute() {
	e.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		users, err := e.auth.ListAllUsers(r.Context())
		if err != nil {
			e.logger.Error(err, "unable to list users")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		content := templates.AdminPage(users)
		if err := templates.Layout("Admin", content).Render(r.Context(), w); err != nil {
			e.logger.Error(err, "unable to GET /admin")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

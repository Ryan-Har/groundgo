package enforcer

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/Ryan-Har/groundgo/web/templates"
	"github.com/google/uuid"
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
			e.log.Error("unable to GET /login", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	e.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		defer e.log.Debug("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			e.log.Error("parsing form from POST /login", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		e.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := e.auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				e.log.Error("returning login error from POST /login", "err", err)
			}
			return
		}
		if !passwd.Authenticate(password, *user.PasswordHash) {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				e.log.Error("returning login error from POST /login", "err", err)
			}
			return
		}

		session, err := e.session.Create(r.Context(), &user.ID)
		if err != nil {
			e.log.Error("creating session", "err", err)
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
			e.log.Error("unable to GET /signup", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	e.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		defer e.log.Debug("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			e.log.Error("parsing form from POST /signup", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		e.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			if err := templates.SignupError("Passwords do not match").Render(r.Context(), w); err != nil {
				e.log.Error("returning signup error from POST /signup", "err", err)
			}
			return
		}

		if exists, _ := e.auth.CheckEmailExists(r.Context(), email); exists {
			if err := templates.SignupError("Account already exists").Render(r.Context(), w); err != nil {
				e.log.Error("returning signup error from POST /signup", "err", err)
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
				e.log.Error("returning signup error from POST /signup", "err", err)
			}
			return
		}

		session, err := e.session.Create(r.Context(), &user.ID)
		if err != nil {
			e.log.Error("creating session", "err", err)
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
	// full admin page
	e.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		users, err := e.auth.ListAllUsers(r.Context())
		if err != nil {
			e.log.Error("unable to list users", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		content := templates.AdminPage(users)
		if err := templates.Layout("Admin", content).Render(r.Context(), w); err != nil {
			e.log.Error("unable to GET /admin", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// partial for getting a single user by ID. Populates a single row in the table
	e.HandleFunc("GET /admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
		}

		user, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			e.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// partial for edit-row, allowing the modification of a single user within the admin page
	e.HandleFunc("GET /admin/users/{id}/edit-row", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = templates.UserRowEditPartial(user).Render(r.Context(), w)
		if err != nil {
			e.log.Error("unable to render UserRowEditPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// partial for getting a single user by ID. Populates a single row in the table
	e.HandleFunc("PUT /admin/users/{id}/claims", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		claimSlice := r.Form["claims"]

		claims := make(models.Claims)

		for _, claimStr := range claimSlice {
			parts := strings.SplitN(claimStr, ":", 2)
			resource := parts[0]
			role := models.Role("")
			if len(parts) > 1 {
				role = models.Role(parts[1])
			}
			claims[resource] = role
		}

		// get a copy of the user model before the update for comparison, to update state if neccessary
		var beforeUpdateUser *models.User
		if _, exists := claims["/"]; exists {
			beforeUpdateUser, err = e.auth.GetUserByID(r.Context(), usrID)
			if err != nil {
				e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if err := e.auth.UpdateUserClaims(r.Context(), usrID, claims); err != nil {
			e.log.Error("unable to update user claim", "err", err)
		}

		afterUpdateUser, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		statsUpdateHeader := fmt.Sprintf(`{"update-stats":{"admin":%d}}`, adminCountDelta(beforeUpdateUser, afterUpdateUser))
		w.Header().Set("HX-Trigger", statsUpdateHeader)

		if err := templates.UserRow(afterUpdateUser).Render(r.Context(), w); err != nil {
			e.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// partial for hard deleting a user
	e.HandleFunc("DELETE /admin/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "error", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
		}

		user, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: add persistent logging for This kind of thing
		if err := e.auth.HardDeleteUser(r.Context(), usrID); err != nil {
			e.log.Error("unable to delete user", "id", id, "err", err)
			http.Error(w, "unable to delete user", http.StatusInternalServerError)
		}

		var statsUpdateHeader string
		switch user.IsActive {
		case true:
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1}}`
			}
		case false:
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1}}`
			}
		}

		w.Header().Set("HX-Trigger", statsUpdateHeader)
	})

	// partial for disabling a single user by ID. Populates a single row in the table
	e.HandleFunc("POST /admin/users/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := e.auth.SoftDeleteUser(r.Context(), usrID); err != nil {
			e.log.Error("unable to disable user", "id", id, "err", err)
			http.Error(w, "unable to disable user", http.StatusInternalServerError)
		}

		user, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		statsUpdateHeader := `{"update-stats":{"active":-1,"inactive":1}}`
		w.Header().Set("HX-Trigger", statsUpdateHeader)

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			e.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	// partial for enabling a single user by ID. Populates a single row in the table
	e.HandleFunc("POST /admin/users/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			e.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := e.auth.RestoreUser(r.Context(), usrID); err != nil {
			e.log.Error("unable to enable user", "id", id, "err", err)
			http.Error(w, "unable to enable user", http.StatusInternalServerError)
		}

		user, err := e.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			e.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		statsUpdateHeader := `{"update-stats":{"active":1,"inactive":-1}}`
		w.Header().Set("HX-Trigger", statsUpdateHeader)

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			e.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

// adminCountDelta compares the roles of beforeUpdateUser and afterUpdateUser
// and determines if the admin user count should be adjusted.
//
// Returns:
// - +1 if the user's role was promoted from below admin to admin or higher (increment admin count)
// - -1 if the user's role was demoted from admin or higher to below admin (decrement admin count)
// - 0 if no change to admin status or if beforeUpdateUser is nil
//
// Parameters:
// - beforeUpdateUser: pointer to the User before update; may be nil if no prior data
// - afterUpdateUser: pointer to the User after update; assumed non-nil
func adminCountDelta(beforeUpdateUser, afterUpdateUser *models.User) int {
	// No change if before is nil (e.g. new user or missing claim)
	if beforeUpdateUser == nil {
		return 0
	}

	wasAdmin := beforeUpdateUser.Role.AtLeast(models.RoleAdmin)
	isAdmin := afterUpdateUser.Role.AtLeast(models.RoleAdmin)

	switch {
	case !wasAdmin && isAdmin:
		// Role went from below admin to admin or higher
		return +1
	case wasAdmin && !isAdmin:
		// Role went from admin or higher to below admin
		return -1
	default:
		return 0
	}
}

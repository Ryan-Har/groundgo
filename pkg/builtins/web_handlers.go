package builtins

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/Ryan-Har/groundgo/web/templates"
	"github.com/google/uuid"
)

func (h *Handler) handleLoginGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		content := templates.LoginPage()
		if err := templates.Layout("Login", content).Render(r.Context(), w); err != nil {
			h.log.Error("unable to GET /login", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleLoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			h.log.Error("parsing form from POST /login", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		h.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := h.auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				h.log.Error("returning login error from POST /login", "err", err)
			}
			return
		}
		if !passwd.Authenticate(password, *user.PasswordHash) {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				h.log.Error("returning login error from POST /login", "err", err)
			}
			return
		}

		session, err := h.session.Create(r.Context(), user.ID)
		if err != nil {
			h.log.Error("creating session", "err", err)
		}

		// TODO: Make secure before release
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
			Path:     "/",
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) handleSignupGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		content := templates.SignupPage()
		if err := templates.Layout("Signup", content).Render(r.Context(), w); err != nil {
			h.log.Error("unable to GET /signup", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleSignupPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			h.log.Error("parsing form from POST /signup", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		h.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			if err := templates.SignupError("Passwords do not match").Render(r.Context(), w); err != nil {
				h.log.Error("returning signup error from POST /signup", "err", err)
			}
			return
		}

		if exists, _ := h.auth.CheckEmailExists(r.Context(), email); exists {
			if err := templates.SignupError("Account already exists").Render(r.Context(), w); err != nil {
				h.log.Error("returning signup error from POST /signup", "err", err)
			}
			return
		}

		user, err := h.auth.CreateUser(r.Context(), models.CreateUserParams{
			Email:    email,
			Password: &password,
			Role:     "user",
			Claims:   models.Claims{},
		})
		if err != nil {
			if err := templates.SignupError("Unable to create user, please try again later.").Render(r.Context(), w); err != nil {
				h.log.Error("returning signup error from POST /signup", "err", err)
			}
			return
		}

		session, err := h.session.Create(r.Context(), user.ID)
		if err != nil {
			h.log.Error("creating session", "err", err)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
			Path:     "/",
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) handleAdminGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		users, err := h.auth.ListAllUsers(r.Context())
		if err != nil {
			h.log.Error("unable to list users", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		content := templates.AdminPage(users)
		if err := templates.Layout("Admin", content).Render(r.Context(), w); err != nil {
			h.log.Error("unable to GET /admin", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleAdminUserRowGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			h.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleAdminUserRowEditGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := templates.UserRowEditPartial(user).Render(r.Context(), w); err != nil {
			h.log.Error("unable to render UserRowEditPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleAdminUserUpdatePut() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		var params models.UpdateUserByIDParams

		if err := r.ParseForm(); err != nil {
			h.log.Error("failed to parse form")
			http.Error(w, "failed to parse form", http.StatusBadRequest)
			return
		}
		role := models.Role(r.FormValue("role"))

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

		params.ID = usrID
		params.Role = &role
		params.Claims = &claims

		// get a copy of the user model before the update for comparison, to update state if neccessary
		var beforeUpdateUser *models.User
		beforeUpdateUser, err = h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		afterUpdateUser, err := h.auth.UpdateUserByID(r.Context(), params)
		if err != nil {
			h.log.Error("failed to update user by ID", "err", err)
			http.Error(w, "failed to update user", http.StatusInternalServerError)
		}

		statsUpdateHeader := fmt.Sprintf(`{"update-stats":{"admin":%d}}`, adminCountDelta(beforeUpdateUser, afterUpdateUser))
		w.Header().Set("HX-Trigger", statsUpdateHeader)

		if err := templates.UserRow(afterUpdateUser).Render(r.Context(), w); err != nil {
			h.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleAdminUserDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "error", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: add persistent logging for This kind of thing
		if err := h.auth.HardDeleteUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to delete user", "id", id, "err", err)
			http.Error(w, "unable to delete user", http.StatusInternalServerError)
			return
		}

		var statsUpdateHeader string
		if user.IsActive {
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1}}`
			}
		} else {
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1}}`
			}
		}

		w.Header().Set("HX-Trigger", statsUpdateHeader)
	}
}

func (h *Handler) handleAdminUserDisable() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := h.auth.SoftDeleteUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to disable user", "id", id, "err", err)
			http.Error(w, "unable to disable user", http.StatusInternalServerError)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("HX-Trigger", `{"update-stats":{"active":-1,"inactive":1}}`)

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			h.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (h *Handler) handleAdminUserEnable() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := h.auth.RestoreUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to enable user", "id", id, "err", err)
			http.Error(w, "unable to enable user", http.StatusInternalServerError)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("HX-Trigger", `{"update-stats":{"active":1,"inactive":-1}}`)

		if err := templates.UserRow(user).Render(r.Context(), w); err != nil {
			h.log.Error("unable to render UserRowPartial", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// adminCountDelta compares the roles of beforeUpdateUser and afterUpdateUser
// and determines if the admin user count should be adjusteh.
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

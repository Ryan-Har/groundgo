package web

import (
	"net/http"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/Ryan-Har/groundgo/web/templates"
	"github.com/go-logr/logr"
)

type WebHandler struct {
	logger logr.Logger
	auth   authstore.AuthStore
}

func New(l logr.Logger, auth authstore.AuthStore) *WebHandler {
	return &WebHandler{
		logger: l,
		auth:   auth,
	}
}

// Mux defines the interface SetRoutes expects for registering handlers.
// It covers the methods typically found on http.ServeMux and many other routers.
type Mux interface {
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
	Handle(pattern string, handler http.Handler)
}

func (h *WebHandler) SetLogger(logger logr.Logger) {
	h.logger = logger
}

// SetRoutes registers the library's HTTP routes on the provided mux
func (h *WebHandler) SetRoutes(mux Mux) {
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		h.logger.V(3).Info("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
		content := templates.LoginPage()
		if err := templates.Layout("Login", content).Render(r.Context(), w); err != nil {
			h.logger.Error(err, "unable to GET /login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		h.logger.V(3).Info("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
		defer h.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			h.logger.Error(err, "parsing form from POST /login")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		h.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := h.auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				h.logger.Error(err, "returning login error from POST /signup")
			}
			return
		}
		if !passwd.Authenticate(password, *user.PasswordHash) {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				h.logger.Error(err, "returning login error from POST /signup")
			}
			return
		}

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /signup", func(w http.ResponseWriter, r *http.Request) {
		h.logger.V(3).Info("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
		content := templates.SignupPage()
		if err := templates.Layout("Signup", content).Render(r.Context(), w); err != nil {
			h.logger.Error(err, "unable to GET /signup")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		h.logger.V(3).Info("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
		defer h.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			h.logger.Error(err, "parsing form from POST /signup")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		h.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			if err := templates.SignupError("Passwords do not match").Render(r.Context(), w); err != nil {
				h.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		if exists, _ := h.auth.CheckEmailExists(r.Context(), email); exists {
			if err := templates.SignupError("Account already exists").Render(r.Context(), w); err != nil {
				h.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		if _, err := h.auth.CreateUser(r.Context(), models.CreateUserParams{
			Email:    email,
			Password: &password,
			Role:     "user",
		}); err != nil {
			if err := templates.SignupError("Unable to create user, please try again later.").Render(r.Context(), w); err != nil {
				h.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})

}

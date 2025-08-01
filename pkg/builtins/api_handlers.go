package builtins

import (
	"encoding/json"
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
)

func (h *Handler) handleAPITokenVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())
		// middleware will have already denied the user by this point
		// TODO: implement properly, returns 200 even without a bearer
		tokenstr, ok := r.Context().Value(enforcer.JWTContextKey).(string)
		if !ok || tokenstr == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) handleAPITokenRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		tokenstr, ok := r.Context().Value(enforcer.JWTContextKey).(string)
		if !ok || tokenstr == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		newToken, err := h.token.RefreshTokenStr(r.Context(), tokenstr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]string{"token": newToken}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func (h *Handler) handleAPILoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		var creds struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByEmail(r.Context(), creds.Email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !passwd.Authenticate(creds.Password, *user.PasswordHash) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := h.token.IssueToken(user)
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		resp := map[string]string{"token": token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

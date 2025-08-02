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

		refreshTokenCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if err == http.ErrNoCookie {
				http.Error(w, "refresh token not found", http.StatusUnauthorized)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		refreshTokenStr := refreshTokenCookie.Value

		tokenPair, err := h.token.RotateRefreshToken(r.Context(), refreshTokenStr)
		if err != nil {
			// TODO: Handle errors from the rotation logic (e.g., invalid token)
			http.Error(w, "failed to refresh token", http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    tokenPair.RefreshToken,
			HttpOnly: true,
			Secure:   true, // In production
			SameSite: http.SameSiteStrictMode,
			Path:     "/api/v1/token/refresh",
		})

		resp := map[string]string{"token": tokenPair.AccessToken}
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

		tokenPair, err := h.token.IssueTokenPair(r.Context(), user)
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		// It's best practice to send the refresh token in a secure, HttpOnly cookie
		// to protect against XSS, but for simplicity, a JSON response also works.
		// TODO: Make secure before release
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    tokenPair.RefreshToken,
			HttpOnly: true,
			Secure:   false, // Set to true in production
			//SameSite: http.SameSiteStrictMode,
			Path: "/api/v1/token/refresh", // Only send it to the refresh endpoint
		})

		resp := map[string]string{"token": tokenPair.AccessToken}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

package builtins

import (
	"encoding/json"
	"net/http"

	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/api"
	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
)

func (h *Handler) handleAPITokenVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		// middleware will have already denied the user by this point
		tokenstr, ok := r.Context().Value(enforcer.JWTContextKey).(string)
		if !ok || tokenstr == "" {
			api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "invalid token")
			return
		}

		if _, err := h.token.ParseAccessTokenAndValidate(r.Context(), tokenstr); err != nil {
			api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "invalid token")
			return
		}

		api.RespondJSONAndLog(w, h.log, http.StatusOK, true, "valid token")
	}
}

func (h *Handler) handleAPITokenRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		refreshTokenCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if err == http.ErrNoCookie {
				api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "missing refresh token")
				return
			}
			h.log.Error("failed to read cookie", "err", err)
			api.InternalServerError(w)
			return
		}

		refreshTokenStr := refreshTokenCookie.Value

		tokenPair, err := h.token.RotateRefreshToken(r.Context(), refreshTokenStr)
		if err != nil {
			switch err {
			case tokenstore.ErrInvalidToken, tokenstore.ErrTokenReuseDetected:
				api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "invalid, expired or reused token")
			default:
				api.InternalServerError(w)
			}
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
		api.RespondJSONAndLog(w, h.log, http.StatusOK, true, resp)
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
			api.RespondJSONAndLog(w, h.log, http.StatusBadRequest, false, "invalid body format")
			return
		}

		user, err := h.auth.GetUserByEmail(r.Context(), creds.Email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "invalid credentials")
			return
		}

		if !passwd.Authenticate(creds.Password, *user.PasswordHash) {
			api.RespondJSONAndLog(w, h.log, http.StatusUnauthorized, false, "invalid credentials")
			return
		}

		tokenPair, err := h.token.IssueTokenPair(r.Context(), user)
		if err != nil {
			h.log.Error("failed to generate token", "err", err)
			api.InternalServerError(w)
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
		api.RespondJSONAndLog(w, h.log, http.StatusOK, true, resp)
	}
}

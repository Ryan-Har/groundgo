package builtins

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/api"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

func (h *Handler) handleAPITokenVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		// middleware will have already denied the user by this point
		tokenstr, ok := r.Context().Value(enforcer.JWTContextKey).(string)
		if !ok || tokenstr == "" {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidToken)
			return
		}

		validatedToken, err := h.token.ParseAccessTokenAndValidate(r.Context(), tokenstr)
		if err != nil {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidToken)
			return
		}

		api.RespondJSONAndLog(w, h.log, http.StatusOK,
			api.TokenValidationResponse{
				ExpiresAt: &validatedToken.ExpiresAt.Time,
				Valid:     true,
			})
	}
}

func (h *Handler) handleAPITokenRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		refreshTokenCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if err == http.ErrNoCookie {
				api.ReturnError(w, h.log, api.UnauthorizedMissingToken)
				return
			}
			h.log.Error("failed to read cookie", "err", err)
			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		refreshTokenStr := refreshTokenCookie.Value

		tokenPair, err := h.token.RotateRefreshToken(r.Context(), refreshTokenStr)
		if err != nil {
			switch err {
			case tokenstore.ErrInvalidToken, tokenstore.ErrTokenReuseDetected:
				api.ReturnError(w, h.log, api.UnauthorizedInvalidToken)
			default:
				api.ReturnError(w, h.log, api.InternalServerError)
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

		resp := api.TokenResponse{
			Token:     tokenPair.AccessToken,
			ExpiresIn: int64(tokenPair.ExpiresInSeconds),
		}
		api.RespondJSONAndLog(w, h.log, http.StatusOK, resp)
	}
}

func (h *Handler) handleAPILoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		var creds api.LoginRequest

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			api.ReturnError(w, h.log, api.BadRequestInvalidJSON)
			return
		}

		user, err := h.auth.GetUserByEmail(r.Context(), creds.Email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidCredentials)
			return
		}

		if !passwd.Authenticate(creds.Password, *user.PasswordHash) {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidCredentials)
			return
		}

		tokenPair, err := h.token.IssueTokenPair(r.Context(), user)
		if err != nil {
			h.log.Error("failed to generate token", "err", err)
			api.ReturnError(w, h.log, api.InternalServerError)
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

		resp := api.TokenResponse{
			Token:     tokenPair.AccessToken,
			ExpiresIn: int64(tokenPair.ExpiresInSeconds),
		}
		api.RespondJSONAndLog(w, h.log, http.StatusOK, resp)
	}
}

func (h *Handler) handleAPILogoutPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		tokenstr, ok := r.Context().Value(enforcer.JWTContextKey).(string)
		if !ok || tokenstr == "" {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidToken)
			return
		}

		//revoke short token
		validatedToken, err := h.token.ParseAccessTokenAndValidate(r.Context(), tokenstr)
		if err != nil {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidToken)
			return
		}

		if err := h.token.RevokeAccessToken(r.Context(), validatedToken); err != nil {
			h.log.Debug("failed to revoke access token", "err", err)
			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		//overwrite existing refresh cookie so that the current client cannot refresh

		// It's best practice to send the refresh token in a secure, HttpOnly cookie
		// to protect against XSS, but for simplicity, a JSON response also works.
		// TODO: Make secure before release
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			HttpOnly: true,
			Secure:   false, // Set to true in production
			//SameSite: http.SameSiteStrictMode,
			Path:    "/api/v1/token/refresh", // Only send it to the refresh endpoint
			Expires: time.Unix(0, 0),
			MaxAge:  -1,
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) handleAPIGetUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := api.BadRequestValidation("invalid uuid format in path")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			var dbErr *models.DatabaseError
			if errors.As(err, &dbErr) {
				if errors.Is(dbErr, sql.ErrNoRows) {
					code, resp := api.NotFound(fmt.Sprintf("user with id %s not found", usrID))
					api.RespondJSONAndLog(w, h.log, code, resp)
					return
				}
			}
			var valErr *models.ValidationError
			if errors.As(err, &valErr) {
				code, resp := api.BadRequestValidation(valErr.Error())
				api.RespondJSONAndLog(w, h.log, code, resp)
				return
			}

			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		userResp := api.UserResponse{
			User: *user,
		}
		// If found, respond with a 200 OK and the user data in JSON
		api.RespondJSONAndLog(w, h.log, http.StatusOK, userResp)
	}
}

func (h *Handler) handleAPIGetOwnUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		// something has gone wrong with the middleware
		user, ok := r.Context().Value(enforcer.UserContextKey).(*models.User)
		if !ok {
			h.log.Error("user not found in context for GetOwnUser")
			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		// uuid must be nil, guest session
		if user.ID == uuid.Nil {
			code, resp := api.NewError(http.StatusUnauthorized, api.ErrAuthRequired, "")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		// user auth is successful, our expected route
		api.RespondJSONAndLog(w, h.log, http.StatusOK, api.UserResponse{User: *user})
	}
}

func (h *Handler) HandleAPIChangeOwnPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		var puReq api.PasswordUpdateRequest

		// something has gone wrong with the middleware
		user, ok := r.Context().Value(enforcer.UserContextKey).(*models.User)
		if !ok {
			h.log.Error("user not found in context for GetOwnUser")
			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		// uuid must be nil, guest session
		if user.ID == uuid.Nil {
			code, resp := api.NewError(http.StatusUnauthorized, api.ErrAuthRequired, "")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		if err := json.NewDecoder(r.Body).Decode(&puReq); err != nil {
			api.ReturnError(w, h.log, api.BadRequestInvalidJSON)
			return
		}

		if !passwd.Authenticate(puReq.CurrentPassword, *user.PasswordHash) {
			api.ReturnError(w, h.log, api.UnauthorizedInvalidCredentials)
			return
		}

		//update password
		if err := h.auth.UpdateUserPassword(r.Context(), user.ID, puReq.NewPassword); err != nil {
			h.log.Error("failed to update user password", "err", err)
			api.ReturnError(w, h.log, api.InternalServerError)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

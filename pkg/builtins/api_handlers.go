package builtins

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Ryan-Har/groundgo/api"
	"github.com/Ryan-Har/groundgo/internal/db"
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
				api.ReturnError(w, h.log, api.UnauthorizedMissingRefreshToken)
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
			Path: h.apiBaseRoute + "/auth/refresh", // Only send it to the refresh endpoint
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

		if err := creds.Validate(); err != nil {
			int, resp := api.BadRequestValidation(err.Error())
			api.RespondJSONAndLog(w, h.log, int, resp)
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
			Path: h.apiBaseRoute + "/auth/refresh", // Only send it to the refresh endpoint
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
			Path:    h.apiBaseRoute + "/auth/refresh", // Only send it to the refresh endpoint
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
			h.handleErrors(w, err)
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

		if err := puReq.Validate(); err != nil {
			int, resp := api.BadRequestValidation(err.Error())
			api.RespondJSONAndLog(w, h.log, int, resp)
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

func (h *Handler) handleAPIGetUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		var params models.GetPaginatedUsersParams
		q := r.URL.Query()

		// page required
		pageStr := q.Get("page")
		if pageStr == "" {
			code, resp := api.BadRequestValidation("page parameter is required")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		page, err := strconv.Atoi(pageStr)
		if err != nil {
			code, resp := api.BadRequestValidation(fmt.Sprintf("invalid page: %s", pageStr))
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		params.Page = page

		//limit required
		limitStr := q.Get("limit")
		if limitStr == "" {
			code, resp := api.BadRequestValidation("limit parameter is required")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			code, resp := api.BadRequestValidation(fmt.Sprintf("invalid limit: %s", pageStr))
			api.RespondJSONAndLog(w, h.log, code, resp)
			return

		}
		params.Limit = limit

		// role optional, uses unmarshalText
		if roleStr := q.Get("role"); roleStr != "" {
			var role models.Role
			if err := role.UnmarshalText([]byte(roleStr)); err != nil {
				h.handleJSONDecodeError(w, err)
				return
			}
			params.Role = &role
		}

		if err := params.Validate(); err != nil {
			code, resp := api.BadRequestValidation(err.Error())
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		usersPtr, meta, err := h.auth.ListUsersPaginatedWithRoleFilter(r.Context(), params)
		if err != nil {
			h.log.Error("failed to get paginated users with role filter", "err", err)
			api.ReturnError(w, h.log, api.InternalServerError)
			return
		}

		if len(usersPtr) == 0 {
			code, resp := api.NotFound("no results")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		// Convert []*User -> []User for API response
		usersVal := make([]models.User, len(usersPtr))
		for i, u := range usersPtr {
			if u != nil {
				usersVal[i] = *u
			}
		}

		userResp := api.GetUsersResponse{
			Users: usersVal,
			Meta:  meta,
		}

		// If found, respond with a 200 OK and the user data in JSON
		api.RespondJSONAndLog(w, h.log, http.StatusOK, userResp)
	}
}

func (h *Handler) handleAPICreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		var params models.CreateUserParams

		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			h.handleJSONDecodeError(w, err)
			return
		}

		if err := params.Validate(); err != nil {
			h.handleErrors(w, err)
			return
		}

		user, err := h.auth.CreateUser(r.Context(), params)
		if err != nil {
			h.handleErrors(w, err)
			return
		}

		api.RespondJSONAndLog(w, h.log, http.StatusCreated, api.UserResponse{User: *user})
	}
}

func (h *Handler) handleAPIUpdateUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := api.BadRequestValidation("invalid uuid format in path")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		var params api.UserUpdateRequest

		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			h.handleJSONDecodeError(w, err)
			return
		}

		// no need to validate the request here, it's done at the store level when updating user
		reqStruct := models.UpdateUserByIDParams{
			ID:       usrID,
			Email:    params.Email,
			Claims:   params.Claims,
			IsActive: params.IsActive,
			Role:     params.Role,
		}

		user, err := h.auth.UpdateUserByID(r.Context(), reqStruct)
		if err != nil {
			h.handleErrors(w, err)
			return
		}

		api.RespondJSONAndLog(w, h.log, http.StatusCreated, api.UserResponse{User: *user})
	}
}

func (h *Handler) handleAPIDeleteUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.log.Debug("Access", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := api.BadRequestValidation("invalid uuid format in path")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		if err := h.auth.HardDeleteUser(r.Context(), usrID); err != nil {
			h.handleErrors(w, err)
			return
		}

		w.WriteHeader(http.StatusAccepted)
	}
}

func (h *Handler) handleJSONDecodeError(w http.ResponseWriter, err error) {
	var valErr *models.ValidationError
	if errors.As(err, &valErr) {
		code, resp := api.BadRequestValidation(valErr.Error())
		api.RespondJSONAndLog(w, h.log, code, resp)
		return
	}

	var tranErr *models.TransformationError
	if errors.As(err, &tranErr) {
		h.log.Error("failed to transform data when decoding json", "err", err)
		api.ReturnError(w, h.log, api.InternalServerError)
		return
	}

	api.ReturnError(w, h.log, api.BadRequestInvalidJSON)

}

func (h *Handler) handleErrors(w http.ResponseWriter, err error) {
	var valErr *models.ValidationError
	if errors.As(err, &valErr) {
		code, resp := api.BadRequestValidation(err.Error())
		api.RespondJSONAndLog(w, h.log, code, resp)
		return
	}
	// specific db errors
	var dupErr *db.DuplicateKeyError
	if errors.As(err, &dupErr) {
		code, resp := api.ResourceConflict(fmt.Sprintf("%s already exists", dupErr.GetField()))
		api.RespondJSONAndLog(w, h.log, code, resp)
		return
	}
	// catch-all db errors
	var dbErr *models.DatabaseError
	if errors.As(err, &dbErr) {
		if errors.Is(err, sql.ErrNoRows) {
			code, resp := api.NotFound("user with specified ID not found")
			api.RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		h.log.Error("authstore error", "err", dbErr)
		api.ReturnError(w, h.log, api.InternalServerError)
		return
	}

	var tranErr *models.TransformationError
	if errors.As(err, &tranErr) {
		h.log.Error("transformation error", "err", tranErr)
		api.ReturnError(w, h.log, api.InternalServerError)
		return
	}
	// any other error
	h.log.Debug("unknown authstore error", "err", err)
	api.ReturnError(w, h.log, api.InternalServerError)
}

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Ryan-Har/groundgo/internal/db"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
	"github.com/Ryan-Har/groundgo/pkg/middlewarectx"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

type Handler struct {
	auth    auth
	session session
	token   token
	cookie  cookie
	log     *slog.Logger
}

func New(logger *slog.Logger, auth auth, session session, token token, cookie cookie) *Handler {
	return &Handler{
		auth:    auth,
		session: session,
		token:   token,
		cookie:  cookie,
		log:     logger,
	}
}

func (h *Handler) HandleAPITokenVerify() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// middleware will have already denied the user by this point
		tokenstr, ok := middlewarectx.JWTFromContext(r.Context())
		if !ok || tokenstr == "" {
			ReturnError(w, h.log, UnauthorizedInvalidToken)
			return
		}

		validatedToken, err := h.token.ParseAccessTokenAndValidate(r.Context(), tokenstr)
		if err != nil {
			ReturnError(w, h.log, UnauthorizedInvalidToken)
			return
		}

		RespondJSONAndLog(w, h.log, http.StatusOK,
			TokenValidationResponse{
				ExpiresAt: &validatedToken.ExpiresAt.Time,
				Valid:     true,
			})
	}
}

func (h *Handler) HandleAPITokenRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		refreshTokenCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if err == http.ErrNoCookie {
				ReturnError(w, h.log, UnauthorizedMissingRefreshToken)
				return
			}
			h.log.Error("failed to read cookie", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		refreshTokenStr := refreshTokenCookie.Value

		tokenPair, err := h.token.RotateRefreshToken(r.Context(), refreshTokenStr)
		if err != nil {
			switch err {
			case tokenstore.ErrInvalidToken, tokenstore.ErrTokenReuseDetected:
				ReturnError(w, h.log, UnauthorizedInvalidToken)
			default:
				ReturnError(w, h.log, InternalServerError)
			}
			return
		}

		if err := h.cookie.SetRefreshTokenCookie(w, tokenPair.RefreshToken, nil); err != nil {
			h.log.Error("failed to set refresh token cookie", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		resp := TokenResponse{
			Token:     tokenPair.AccessToken,
			ExpiresIn: int64(tokenPair.ExpiresInSeconds),
		}
		RespondJSONAndLog(w, h.log, http.StatusOK, resp)
	}
}

func (h *Handler) HandleAPILoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var creds LoginRequest

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			ReturnError(w, h.log, BadRequestInvalidJSON)
			return
		}

		if err := creds.Validate(); err != nil {
			int, resp := BadRequestValidation(err.Error())
			RespondJSONAndLog(w, h.log, int, resp)
			return
		}

		user, err := h.auth.GetUserByEmail(r.Context(), creds.Email)
		if err != nil || user.PasswordHash == nil || !user.IsActive {
			ReturnError(w, h.log, UnauthorizedInvalidCredentials)
			return
		}

		if !passwd.Authenticate(creds.Password, *user.PasswordHash) {
			ReturnError(w, h.log, UnauthorizedInvalidCredentials)
			return
		}

		tokenPair, err := h.token.IssueTokenPair(r.Context(), user)
		if err != nil {
			h.log.Error("failed to generate token", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		if err := h.cookie.SetRefreshTokenCookie(w, tokenPair.RefreshToken, nil); err != nil {
			h.log.Error("failed to set refresh token cookie", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		resp := TokenResponse{
			Token:     tokenPair.AccessToken,
			ExpiresIn: int64(tokenPair.ExpiresInSeconds),
		}
		RespondJSONAndLog(w, h.log, http.StatusOK, resp)
	}
}

func (h *Handler) HandleAPILogoutPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		tokenstr, ok := middlewarectx.JWTFromContext(r.Context())
		if !ok || tokenstr == "" {
			ReturnError(w, h.log, UnauthorizedInvalidToken)
			return
		}

		//revoke short token
		validatedToken, err := h.token.ParseAccessTokenAndValidate(r.Context(), tokenstr)
		if err != nil {
			ReturnError(w, h.log, UnauthorizedInvalidToken)
			return
		}

		if err := h.token.RevokeAccessToken(r.Context(), validatedToken); err != nil {
			h.log.Debug("failed to revoke access token", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		//overwrite existing refresh cookie so that the current client cannot refresh
		if err := h.cookie.ClearRefreshTokenCookie(w); err != nil {
			h.log.Error("failed to set refresh token cookie", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) HandleAPIGetUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := BadRequestValidation("invalid uuid format in path")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.handleErrors(w, err)
			return
		}

		userResp := UserResponse{
			User: *user,
		}
		// If found, respond with a 200 OK and the user data in JSON
		RespondJSONAndLog(w, h.log, http.StatusOK, userResp)
	}
}

func (h *Handler) HandleAPIGetOwnUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// something has gone wrong with the middleware
		user, ok := middlewarectx.UserFromContext(r.Context())
		if !ok {
			h.log.Error("user not found in context for GetOwnUser")
			ReturnError(w, h.log, InternalServerError)
			return
		}

		// uuid must be nil, guest session
		if user.ID == uuid.Nil {
			code, resp := NewError(http.StatusUnauthorized, ErrAuthRequired, "")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		// user auth is successful, our expected route
		RespondJSONAndLog(w, h.log, http.StatusOK, UserResponse{User: *user})
	}
}

func (h *Handler) HandleAPIChangeOwnPassword() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var puReq PasswordUpdateRequest

		// something has gone wrong with the middleware
		user, ok := middlewarectx.UserFromContext(r.Context())
		if !ok {
			h.log.Error("user not found in context for GetOwnUser")
			ReturnError(w, h.log, InternalServerError)
			return
		}

		// uuid must be nil, guest session
		if user.ID == uuid.Nil {
			code, resp := NewError(http.StatusUnauthorized, ErrAuthRequired, "")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		if err := json.NewDecoder(r.Body).Decode(&puReq); err != nil {
			ReturnError(w, h.log, BadRequestInvalidJSON)
			return
		}

		if err := puReq.Validate(); err != nil {
			int, resp := BadRequestValidation(err.Error())
			RespondJSONAndLog(w, h.log, int, resp)
			return
		}

		if !passwd.Authenticate(puReq.CurrentPassword, *user.PasswordHash) {
			ReturnError(w, h.log, UnauthorizedInvalidCredentials)
			return
		}

		//update password
		if err := h.auth.UpdateUserPassword(r.Context(), user.ID, puReq.NewPassword); err != nil {
			h.log.Error("failed to update user password", "err", err)
			ReturnError(w, h.log, InternalServerError)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) HandleAPIGetUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var params models.GetPaginatedUsersParams
		q := r.URL.Query()

		// page required
		pageStr := q.Get("page")
		if pageStr == "" {
			code, resp := BadRequestValidation("page parameter is required")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		page, err := strconv.Atoi(pageStr)
		if err != nil {
			code, resp := BadRequestValidation(fmt.Sprintf("invalid page: %s", pageStr))
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		params.Page = page

		//limit required
		limitStr := q.Get("limit")
		if limitStr == "" {
			code, resp := BadRequestValidation("limit parameter is required")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			code, resp := BadRequestValidation(fmt.Sprintf("invalid limit: %s", pageStr))
			RespondJSONAndLog(w, h.log, code, resp)
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
			code, resp := BadRequestValidation(err.Error())
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		usersPtr, meta, err := h.auth.ListUsersPaginatedWithRoleFilter(r.Context(), params)
		if err != nil {
			h.log.Error("failed to get paginated users with role filter", "err", err)
			ReturnError(w, h.log, InternalServerError)
			return
		}

		if len(usersPtr) == 0 {
			code, resp := NotFound("no results")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		// Convert []*User -> []User for API response
		usersVal := make([]models.User, len(usersPtr))
		for i, u := range usersPtr {
			if u != nil {
				usersVal[i] = *u
			}
		}

		userResp := GetUsersResponse{
			Users: usersVal,
			Meta:  meta,
		}

		// If found, respond with a 200 OK and the user data in JSON
		RespondJSONAndLog(w, h.log, http.StatusOK, userResp)
	}
}

func (h *Handler) HandleAPICreateUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

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

		RespondJSONAndLog(w, h.log, http.StatusCreated, UserResponse{User: *user})
	}
}

func (h *Handler) HandleAPIUpdateUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := BadRequestValidation("invalid uuid format in path")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		var params UserUpdateRequest

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

		RespondJSONAndLog(w, h.log, http.StatusCreated, UserResponse{User: *user})
	}
}

func (h *Handler) HandleAPIDeleteUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			code, resp := BadRequestValidation("invalid uuid format in path")
			RespondJSONAndLog(w, h.log, code, resp)
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
		code, resp := BadRequestValidation(valErr.Error())
		RespondJSONAndLog(w, h.log, code, resp)
		return
	}

	var tranErr *models.TransformationError
	if errors.As(err, &tranErr) {
		h.log.Error("failed to transform data when decoding json", "err", err)
		ReturnError(w, h.log, InternalServerError)
		return
	}

	ReturnError(w, h.log, BadRequestInvalidJSON)

}

func (h *Handler) handleErrors(w http.ResponseWriter, err error) {
	var valErr *models.ValidationError
	if errors.As(err, &valErr) {
		code, resp := BadRequestValidation(err.Error())
		RespondJSONAndLog(w, h.log, code, resp)
		return
	}
	// specific db errors
	var dupErr *db.DuplicateKeyError
	if errors.As(err, &dupErr) {
		code, resp := ResourceConflict(fmt.Sprintf("%s already exists", dupErr.GetField()))
		RespondJSONAndLog(w, h.log, code, resp)
		return
	}
	// catch-all db errors
	var dbErr *models.DatabaseError
	if errors.As(err, &dbErr) {
		if errors.Is(err, sql.ErrNoRows) {
			code, resp := NotFound("user with specified ID not found")
			RespondJSONAndLog(w, h.log, code, resp)
			return
		}

		h.log.Error("authstore error", "err", dbErr)
		ReturnError(w, h.log, InternalServerError)
		return
	}

	var tranErr *models.TransformationError
	if errors.As(err, &tranErr) {
		h.log.Error("transformation error", "err", tranErr)
		ReturnError(w, h.log, InternalServerError)
		return
	}
	// any other error
	h.log.Debug("unknown authstore error", "err", err)
	ReturnError(w, h.log, InternalServerError)
}

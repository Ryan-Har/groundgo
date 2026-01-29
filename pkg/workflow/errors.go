package workflow

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrNotAuthenticated   = errors.New("not authenticated")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrTokenRevoked       = errors.New("revoked token use detected")
	ErrTokenReuseDetected = errors.New("token reuse detected")
	ErrInternalServer     = errors.New("internal server error")
	ErrGuestStateDisabled = errors.New("guest state is not enabled")
)

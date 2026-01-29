package workflow

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/apidetector"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/store"
)

type Workflow struct {
	store             store.Store
	log               *slog.Logger
	GuestStateEnabled bool

	apiDetector apidetector.APIRequestDetector
}

func NewWorkflow(s store.Store, a apidetector.APIRequestDetector, guestState bool, log *slog.Logger) *Workflow {
	return &Workflow{
		store:             s,
		log:               log,
		GuestStateEnabled: guestState,
		apiDetector:       a,
	}
}

type Processor interface {
	ResolveUser(r *http.Request) (*models.User, error)
	AuthenticateRequest(r *http.Request) (*models.User, context.Context, error)
	EnsureGuest(r *http.Request, w http.ResponseWriter) (*models.User, context.Context)
}

// ResolveUser attempts to identify the authenticated user associated with the request.
//
// It checks authentication mechanisms in order (e.g. JWT, then session).
// This method does NOT modify the request context or perform any HTTP side effects
// such as setting cookies or issuing redirects.
//
// It is suitable for use in:
//   - API handlers
//   - background logic
//   - authorization checks
//   - non-middleware contexts
//
// If no valid authentication is found, ErrNotAuthenticated is returned.
func (f *Workflow) ResolveUser(r *http.Request) (*models.User, error) {
	// Try JWT-based authentication first
	if user, _, err := f.resolveFromJWT(r); err == nil {
		return user, nil
	}

	// Fallback to session-based authentication
	if user, err := f.resolveFromSession(r); err == nil {
		return user, nil
	}

	return nil, ErrNotAuthenticated
}

// AuthenticateRequest resolves the authenticated user for the request and
// installs the result into the request context.
//
// If a user is already present in the request context, it is reused and no
// additional store lookups are performed.
//
// On success, it returns:
//   - the authenticated user
//   - a derived context containing the user (and optional JWT)
//   - nil error
//
// This method performs NO fallback behavior (such as creating guest users).
// Callers should handle ErrNotAuthenticated explicitly (e.g. via EnsureGuest).
func (f *Workflow) AuthenticateRequest(r *http.Request) (*models.User, context.Context, error) {
	ctx := r.Context()

	// Reuse user already attached to context if present
	if user, ok := UserFromContext(ctx); ok {
		return user, ctx, nil
	}

	// Attempt JWT authentication
	if user, jwt, err := f.resolveFromJWT(r); err == nil {
		ctx = ContextWithUserAndJWT(ctx, user, jwt)
		return user, ctx, nil
	}

	// Attempt session authentication
	if user, err := f.resolveFromSession(r); err == nil {
		ctx = ContextWithUserAndJWT(ctx, user, "")
		return user, ctx, nil
	}

	return nil, ctx, ErrNotAuthenticated
}

// EnsureGuest ensures that the request has an associated guest user.
//
// If guest state is enabled, this may create a new guest session and attach
// it to the response via cookies. The resulting guest user is installed into
// the returned context.
//
// If guest state is disabled, a transient guest user is returned without
// creating any persistent session.
//
// This method is intended for use by authentication middleware when no valid
// authenticated user can be resolved.
func (f *Workflow) EnsureGuest(r *http.Request, w http.ResponseWriter) (*models.User, context.Context) {
	user, err := f.ensureGuestInternal(r, w)
	if err != nil {
		// Caller decides how to handle hard failure (API vs web, etc.)
		return nil, r.Context()
	}

	ctx := ContextWithUserAndJWT(r.Context(), user, "")
	return user, ctx
}

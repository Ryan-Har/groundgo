package workflow

import (
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/google/uuid"
)

// ensureGuestInternal creates or resolves a guest user for the request.
//
// If guest state is enabled, it creates a persistent guest session and sets
// the appropriate cookie on the response. If guest state is disabled, it
// returns a transient guest user without creating any session.
//
// This method performs the underlying storage and cookie operations and
// should not install the result into the request context.
func (f *Workflow) ensureGuestInternal(r *http.Request, w http.ResponseWriter) (*models.User, error) {
	// Stateless guest (no session)
	if !f.GuestStateEnabled {
		return models.NewGuestUser(), nil
	}

	// Create guest session
	guestSession, err := f.store.Session.Create(r.Context(), uuid.Nil)
	if err != nil {
		f.log.Error("unable to create guest session", "err", err)
		return nil, err
	}

	// Set cookie
	if err := f.store.Cookie.SetGuestCookie(w, guestSession.ID, &guestSession.ExpiresAt); err != nil {
		return nil, err
	}

	return models.NewGuestUser(), nil
}

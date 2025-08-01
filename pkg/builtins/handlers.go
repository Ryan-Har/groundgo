package builtins

import (
	"log/slog"

	"github.com/Ryan-Har/groundgo/pkg/store"
)

type Handler struct {
	auth    store.Authstore
	session store.Sessionstore
	token   store.Tokenstore
	log     *slog.Logger
}

func newHandler(logger *slog.Logger, auth store.Authstore, session store.Sessionstore, token store.Tokenstore) *Handler {
	return &Handler{
		auth:    auth,
		session: session,
		token:   token,
		log:     logger,
	}
}

package builtins

import (
	"log/slog"

	"github.com/Ryan-Har/groundgo/pkg/store"
)

type Handler struct {
	auth         store.Authstore
	session      store.Sessionstore
	token        store.Tokenstore
	log          *slog.Logger
	apiBaseRoute string
	baseRoute    string
}

func newHandler(logger *slog.Logger, auth store.Authstore, session store.Sessionstore, token store.Tokenstore, baseRotue, apiBaseRoute string) *Handler {
	return &Handler{
		auth:         auth,
		session:      session,
		token:        token,
		log:          logger,
		baseRoute:    baseRotue,
		apiBaseRoute: apiBaseRoute,
	}
}

package builtins

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/store"
)

type Handler struct {
	auth         store.Authstore
	session      store.Sessionstore
	token        store.Tokenstore
	cookieOpts   CookieOpts
	log          *slog.Logger
	apiBaseRoute string
	baseRoute    string
}

func newHandler(logger *slog.Logger, auth store.Authstore, session store.Sessionstore, token store.Tokenstore, cookie CookieOpts, baseRoute, apiBaseRoute string) *Handler {
	return &Handler{
		auth:         auth,
		session:      session,
		token:        token,
		cookieOpts:   cookie,
		log:          logger,
		baseRoute:    baseRoute,
		apiBaseRoute: apiBaseRoute,
	}
}

type CookieOpts interface {
	ClearRefreshTokenCookie(w http.ResponseWriter) error
	SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
	SetRefreshTokenCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
}

package groundgo

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/Ryan-Har/groundgo/pkg/builtins"
	"github.com/Ryan-Har/groundgo/pkg/enforcer"
	"github.com/Ryan-Har/groundgo/pkg/store"
)

type GroundGo struct {
	logger   *slog.Logger
	config   *Config
	Store    *store.Store
	Enforcer *enforcer.Enforcer
	Builtin  *builtins.Builtin

	// Hold information to initialize services after configuration
	db               *sql.DB
	dbType           store.DBType
	router           enforcer.Router
	sessionsInMemory bool // detertmines if the session store is held in memory only
}

type Option func(*GroundGo)

func WithLogger(l *slog.Logger) Option {
	return func(g *GroundGo) {
		if l != nil {
			g.logger = l
		}
	}
}

func WithSqliteDB(db *sql.DB) Option {
	return func(g *GroundGo) {
		g.db = db
		g.dbType = store.DBTypeSQLite
	}
}

func WithRouter(r enforcer.Router) Option {
	return func(g *GroundGo) {
		g.router = r
	}
}

func WithInMemorySessionStore() Option {
	return func(g *GroundGo) {
		g.sessionsInMemory = true
	}
}

func New(opts ...Option) (*GroundGo, error) {
	gg := &GroundGo{}

	for _, opt := range opts {
		opt(gg)
	}

	gg.logger.Info("starting groundgo")

	// check if database is pingable
	if err := gg.db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	gg.logger.Info("successfully connected to database")

	// load stores now that logging is set
	stores, err := store.New(gg.db, gg.dbType, gg.logger, gg.sessionsInMemory)
	if err != nil {
		return nil, err
	}
	gg.logger.Info("groundgo stores loaded")
	gg.Store = stores

	// load enforcer
	enforcerConfig := &enforcer.Config{
		GuestCookieName:         "session_token",
		GuestCookiePath:         "/",
		GuestCookieSecure:       false,
		RedirectOnAuthErrorPath: "/",
	}
	gg.Enforcer = enforcer.NewEnforcer(gg.logger, gg.router, gg.Store.Auth, gg.Store.Session, gg.Store.Token, enforcerConfig)
	gg.logger.Info("groundgo enforcer loaded")

	gg.Builtin = builtins.New(gg.logger, gg.Enforcer, gg.Store.Auth, gg.Store.Session, gg.Store.Token)
	gg.logger.Info("groundgo builtins loaded")

	gg.logger.Info("groundgo enforcer loaded")
	return gg, nil
}

type Config struct {
	//AllowSignup bool
	//SessionSecret string
	//JWTSecret string
	//TokenTTL time.Duration
	//CustomClaims map[string]any

	IncludeLoginSignupPages bool
}

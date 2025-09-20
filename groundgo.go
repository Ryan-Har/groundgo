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
	logger   *slog.Logger       // slog logger used for internal logging purposes
	Store    *store.Store       // stores available to use (Auth, Session, Token, Cookie)
	Enforcer *enforcer.Enforcer // enforcer handled authentication and authorisation
	Builtin  *builtins.Builtin  // builtin components ready for use

	config *Config

	// Hold information to initialize services after configuration
	db               *sql.DB         // db instance used for persistance
	dbType           store.DBType    // enum indicating type of db
	router           enforcer.Router // router interface required for enforcer.
	sessionsInMemory bool            // detertmines if the session store is held in memory only
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

	gg.config = &Config{
		StoreConfig: store.StoreConfig{
			Logger:           gg.logger,
			DB:               gg.db,
			DBType:           gg.dbType,
			InsecureMode:     true,
			JWTSigningSecret: "tempsigningsecret",
		},
	}

	// load stores now that logging is set
	stores, err := store.New(&gg.config.StoreConfig)
	if err != nil {
		return nil, err
	}
	gg.Store = stores
	gg.logger.Info("groundgo stores loaded")

	gg.config.EnforcerConfig = enforcer.EnforcerConfig{
		Logger:  gg.logger,
		Router:  gg.router,
		Auth:    gg.Store.Auth,
		Session: gg.Store.Session,
		Token:   gg.Store.Token,
		Cookie:  gg.Store.Cookie,
	}

	enf, err := enforcer.New(&gg.config.EnforcerConfig)
	if err != nil {
		return nil, err
	}
	gg.Enforcer = enf
	gg.logger.Info("groundgo enforcer loaded")

	gg.Builtin = builtins.New(gg.logger, gg.Enforcer, gg.Store.Auth, gg.Store.Session, gg.Store.Token, gg.Store.Cookie)
	gg.logger.Info("groundgo builtins loaded")

	return gg, nil
}

type Config struct {
	store.StoreConfig
	enforcer.EnforcerConfig
}

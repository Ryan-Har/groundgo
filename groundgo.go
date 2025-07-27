package groundgo

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/Ryan-Har/groundgo/pkg/access"
	"github.com/Ryan-Har/groundgo/pkg/services"
)

type GroundGo struct {
	logger   *slog.Logger
	config   *Config
	Services *services.Services
	Enforcer *access.Enforcer

	// Hold information to initialize services after configuration
	db               *sql.DB
	dbType           services.DBType
	router           access.Router
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
		g.dbType = services.DBTypeSQLite
	}
}

func WithRouter(r access.Router) Option {
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

	// load services now that logging is set
	gg.Services = services.New(gg.db, gg.dbType, gg.logger, gg.sessionsInMemory)
	gg.logger.Debug("groundgo services loaded")

	// load enforcer
	gg.Enforcer = access.NewEnforcer(gg.logger, gg.router, gg.Services.Auth, gg.Services.Session)
	gg.logger.Info("groundgo enforcer loaded")

	// check if database is pingable
	if err := gg.db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	gg.logger.Debug("successfully connected to database")

	if err := gg.Services.RunMigrations(); err != nil {
		return nil, fmt.Errorf("unable to run migrations: %w", err)
	}
	gg.logger.Debug("successfully run migrations")

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

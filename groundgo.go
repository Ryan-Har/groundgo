package groundgo

import (
	"database/sql"
	"fmt"

	"github.com/Ryan-Har/groundgo/pkg/access"
	"github.com/Ryan-Har/groundgo/pkg/services"
	"github.com/go-logr/logr"
)

type GroundGo struct {
	logger   logr.Logger
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

func WithLogger(l logr.Logger) Option {
	return func(g *GroundGo) {
		// Only set the logger if it's not a no-op logger, allowing for explicit Discard()
		// or if the current logger is Discard() (the default)
		if l.GetSink() != nil || g.logger.GetSink() == nil {
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
	gg := &GroundGo{
		logger: logr.Discard(), // default to no-op logger
	}

	for _, opt := range opts {
		opt(gg)
	}

	gg.logger.V(0).Info("starting groundgo")

	// load services now that logging is set
	gg.logger.V(0).Info("attempting to load services")
	gg.Services = services.New(gg.db, gg.dbType, gg.logger, gg.sessionsInMemory)

	// load enforcer
	gg.logger.V(0).Info("attempting to load enforcer")
	gg.Enforcer = access.NewEnforcer(gg.logger, gg.router, gg.Services.Auth, gg.Services.Session)

	// check if database is pingable
	gg.logger.V(0).Info("attempting ping of database")
	if err := gg.db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	if err := gg.Services.Auth.RunMigrations(); err != nil {
		return nil, fmt.Errorf("unable to run migrations: %w", err)
	}

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

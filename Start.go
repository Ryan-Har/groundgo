package groundgo

import (
	"database/sql"
	"fmt"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/go-logr/logr"
)

type GroundGo struct {
	logger logr.Logger
	Auth   authstore.AuthStore
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
		g.Auth = authstore.NewWithSqliteStore(db, g.logger)
	}
}

func New(opts ...Option) (*GroundGo, error) {
	gg := &GroundGo{
		logger: logr.Discard(), // default to no-op logger
	}

	for _, opt := range opts {
		opt(gg)
	}

	// reset auth logger incase WithLogger wasn't set first
	gg.Auth.SetLogger(gg.logger)

	gg.logger.V(0).Info("starting groundgo")
	// check if database is pingable
	if err := gg.Auth.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	if err := gg.Auth.RunMigrations(); err != nil {
		return nil, fmt.Errorf("unable to run migrations: %w", err)
	}

	return gg, nil
}

package services

import (
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Ryan-Har/groundgo/database"
	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/Ryan-Har/groundgo/internal/tokenstore"
)

type Services struct {
	db      *sql.DB
	logger  *slog.Logger
	Auth    authstore.Store
	Session sessionstore.Store
	Token   tokenstore.TokenStore
	dbType  DBType
}

type DBType string

const (
	DBTypeSQLite   DBType = "sqlite"
	DBTypePostgres DBType = "postgres"
)

// New initializes and returns a Services struct with the appropriate
// subcomponents (e.g., Auth, Session) based on the provided configuration.
//
// The dbType parameter determines the type of database backend used for storage,
// and sessionInMemory controls whether session storage is in-memory or not.
//
// Params:
//   - db: a live database connection
//   - dbType: the type of database (e.g., SQLite, Postgres) used to determine
//     how to initialize subcomponents like Auth
//   - logger: a slog.Logger pointer instance used for logging
//   - sessionInMemory: if true, an in-memory session store is initialized
//
// Example:
//
//	svc := New(db, DBTypeSQLite, logger, true)
func New(db *sql.DB, dbType DBType, logger *slog.Logger, sessionInMemory bool) *Services {
	svc := &Services{
		db:     db,
		logger: logger,
		dbType: dbType,
	}

	switch dbType {
	case DBTypeSQLite:
		svc.Auth = authstore.NewWithSqliteStore(svc.db, svc.logger)
		if sessionInMemory {
			svc.Session = sessionstore.NewInMemory(logger)
		} else {
			svc.Session = sessionstore.NewSqlLite(logger, db)
		}
		svc.Token = tokenstore.NewSqlLite(logger, "tempSecureSigningSecret", time.Minute*15, db)
	}
	return svc
}

func (s *Services) RunMigrations() error {
	switch s.dbType {
	case DBTypeSQLite:
		//defer s.newTimingLogger(time.Now(), "ran database migrations")()
		//s.log.V(0).Info("running auth database migrations")
		return database.RunSqliteMigrations(s.db)
	default:
		return errors.New("unknown database type")
	}
}

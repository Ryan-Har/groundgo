package services

import (
	"database/sql"

	"github.com/Ryan-Har/groundgo/internal/authstore"
	"github.com/Ryan-Har/groundgo/internal/sessionstore"
	"github.com/go-logr/logr"
)

type Services struct {
	db      *sql.DB
	logger  logr.Logger
	Auth    authstore.Store
	Session sessionstore.Store
}

type DBType string

const (
	DBTypeSQLite   = "sqlite"
	DBTypePostgres = "postgres"
)

func New(db *sql.DB, dbType DBType, logger logr.Logger, sessionInMemory bool) *Services {
	svc := &Services{
		db:     db,
		logger: logger,
	}
	if sessionInMemory {
		svc.Session = sessionstore.NewInMemory(logger)
	}
	switch dbType {
	case DBTypeSQLite:
		svc.Auth = authstore.NewWithSqliteStore(svc.db, svc.logger)
	}
	return svc
}


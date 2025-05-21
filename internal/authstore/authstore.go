package authstore

import (
	"context"
	"database/sql"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
)

type AuthStore interface {
	Ping() error
	RunMigrations() error
	CheckEmailExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, args models.CreateUserParams) (models.User, error)
	SetLogger(logger logr.Logger)
}

func NewWithSqliteStore(db *sql.DB, logger logr.Logger) *sqliteAuthStore {
	return &sqliteAuthStore{
		db:      db,
		queries: *sqliteDB.New(db),
		log:     logger,
	}
}

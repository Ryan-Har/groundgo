package authstore

import (
	"context"
	"database/sql"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
)

func NewWithSqliteStore(db *sql.DB, logger logr.Logger) *sqliteAuthStore {
	return &sqliteAuthStore{
		db:      db,
		queries: *sqliteDB.New(db),
		log:     logger,
	}
}

// interface used to provide unified methods to the services from authstore
type Store interface {
	RunMigrations() error
	CheckEmailExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, args models.CreateUserParams) (models.User, error)
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (models.User, error)
}

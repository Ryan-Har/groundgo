package authstore

import (
	"database/sql"
	"log/slog"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
)

func NewWithSqliteStore(db *sql.DB, logger *slog.Logger) *sqliteAuthStore {
	return &sqliteAuthStore{
		db:      db,
		queries: *sqliteDB.New(db),
		log:     logger,
	}
}

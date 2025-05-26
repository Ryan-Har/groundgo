package database

import (
	"database/sql"
	"embed"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	// Register dqlite driver with database/sql
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/sqlite/*.sql
var sqliteMigrations embed.FS

// RunSqliteMigrations applies all pending SQL schema migrations to the provided SQLite database.
//
// This function uses the golang-migrate library and an embedded `io/fs` migration source.
// Migrations are expected to be located in the embedded filesystem path "migrations/sqlite".
// If no new migrations are found, it exits silently unless a non-ErrNoChange error occurs.
//
// Parameters:
//   - db: a *sql.DB connection to the target SQLite database
//
// Returns:
//   - An error if a migration setup or execution step fails, except when the database is already up to date.
//
// Typical usage:
//
//	err := RunSqliteMigrations(db)
//	if err != nil {
//	    log.Fatalf("migration failed: %v", err)
//	}
func RunSqliteMigrations(db *sql.DB) error {
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return err
	}

	source, err := iofs.New(sqliteMigrations, "migrations/sqlite")
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("iofs", source, "sqlite3", driver)
	if err != nil {
		return err
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return err
	}

	return nil
}

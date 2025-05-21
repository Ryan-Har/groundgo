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

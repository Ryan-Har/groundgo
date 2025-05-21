package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"

	"github.com/Ryan-Har/groundgo"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/go-logr/logr"
)

func main() {
	// load logger
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := logr.FromSlogHandler(handler)

	//load db
	db, err := sql.Open("sqlite3", "./groundgo.db")
	if err != nil {
		logger.Error(err, "opening database")
	}
	defer db.Close()

	gg, err := groundgo.New(
		groundgo.WithSqliteDB(db),
		groundgo.WithLogger(logger),
	)

	if err != nil {
		logger.Error(err, "starting groundgo")
	}

	ctx := context.Background()
	gg.Auth.CreateUser(ctx, models.CreateUserParams{
		Email:    "testAdmin@example.com",
		Password: strPtr("MySuperSecurePassword"),
		Role:     "Admin",
	})

	select {}
}

// helper function to easily get string pointers
func strPtr(s string) *string {
	return &s
}

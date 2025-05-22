package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"

	"github.com/Ryan-Har/groundgo"
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

	// create new groundgo instance
	gg, err := groundgo.New(
		groundgo.WithSqliteDB(db),
		groundgo.WithLogger(logger),
	)

	if err != nil {
		logger.Error(err, "starting groundgo")
	}

	// create http mux for use with groundgo
	mainMux := http.NewServeMux()
	gg.Web.SetRoutes(mainMux)

	// now load any additional routed however you like
	mainMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from the main application root!"))
	})

	if err := http.ListenAndServe(":8080", mainMux); err != nil {
		panic("http server failed")
	}
}

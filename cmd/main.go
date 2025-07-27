package main

import (
	"database/sql"
	"log/slog"
	"net/http"
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

	// create http mux for use with groundgo
	mainMux := http.NewServeMux()

	// create new groundgo instance
	gg, err := groundgo.New(
		groundgo.WithSqliteDB(db),
		groundgo.WithLogger(logger),
		groundgo.WithRouter(mainMux),
		groundgo.WithInMemorySessionStore(),
	)

	if err != nil {
		logger.Error(err, "starting groundgo")
	}

	gg.Enforcer.LoadDefaultPolicies()
	// gg.Enforcer.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Write([]byte("Hello from the main application root!"))
	// })
	gg.Enforcer.LoadDefaultRoutes()
	gg.Enforcer.SetPolicy("/admin/users/{id}", "*", models.RoleSystemAdmin)
	mainMux.Handle("GET /", nil)
	//gg.Enforcer.SetPolicy("/admin", "*", models.RoleAdmin)
	// gg.Enforcer.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Write([]byte("Hello from the main application admin page!"))
	// })

	// now load any additional routed however you like
	// uses the same mux but doesn't include the enforcer
	// mainMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Write([]byte("Hello from the main application root!"))
	// })

	if err := http.ListenAndServe(":8080", mainMux); err != nil {
		panic("http server failed")
	}
}

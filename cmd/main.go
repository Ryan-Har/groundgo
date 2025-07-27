package main

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"

	"github.com/Ryan-Har/groundgo"
)

func main() {
	// load logger
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	//load db
	db, err := sql.Open("sqlite3", "./groundgo.db")
	if err != nil {
		logger.Error("failed to open database", "err", err)
	}
	defer db.Close()

	// create http mux for use with groundgo
	mainMux := http.NewServeMux()

	//create new groundgo instance
	gg, err := groundgo.New(
		groundgo.WithSqliteDB(db),
		groundgo.WithLogger(logger),
		groundgo.WithRouter(mainMux),
		groundgo.WithInMemorySessionStore(),
	)

	if err != nil {
		logger.Error("failed to start groundgo", "err", err)
	}

	gg.Enforcer.LoadDefaultPolicies()
	gg.Enforcer.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from the main application root!"))
	})
	gg.Enforcer.LoadDefaultRoutes()
	//gg.Enforcer.SetPolicy("/admin/users/{id}", "*", models.RoleSystemAdmin)
	// gg.Enforcer.SetPolicy("/admin", "*", models.RoleAdmin)

	if err := http.ListenAndServe(":8080", mainMux); err != nil {
		panic("http server failed")
	}
}

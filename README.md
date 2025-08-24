 # groundgo

> An opinionated, extensible authentication and authorization library for Go web applications.

`groundgo` provides a structured foundation for building secure Go-based web projects. It combines role-based access control with hierarchical path-specific claims, session and JWT support, and optional web views or APIs for user management.

---

## Features

-  **Role-based permissions** with 10 predefined levels
-  **Hierarchical path-based overrides** (e.g., `/api/reports` can override `/`)
-  **Method-specific enforcement** with wildcard fallback
-  **Session-based authentication**
-  **Pluggable middleware for auth + authorization**
-  **SQLite support out of the box**
-  **Built-in (optional) HTML templates for user management**
-  **JWT bearer token support** via `tokenstore` (in development)

---

## Installation

```bash
go get github.com/Ryan-Har/groundgo
```

---

## Getting Started

Here's a minimal `main.go` example using `groundgo` with SQLite, session handling, and default routes:

```go
func main() {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	db, err := sql.Open("sqlite3", "./groundgo.db")
	if err != nil {
		logger.Error("failed to open database", "err", err)
	}
	defer db.Close()

	mainMux := http.NewServeMux()

	gg, err := groundgo.New(
		groundgo.WithSqliteDB(db),
		groundgo.WithLogger(logger),
		groundgo.WithRouter(mainMux),
	)

	if err != nil {
		logger.Error("failed to start groundgo", "err", err)
	}

	gg.Enforcer.LoadDefaultPolicies()

	gg.Enforcer.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello from the main application root!"))
	})

	gg.Enforcer.LoadDefaultRoutes()

	if err := http.ListenAndServe(":8080", mainMux); err != nil {
		panic("http server failed")
	}
}
```

---

## Access Control Model

### Roles

`groundgo` uses a numeric role scale from **0 (lowest)** to **100 (highest)**. You define access levels by assigning minimum roles to paths and HTTP methods.

### Hierarchical Claims

You can override a user’s root-level role by assigning claims to specific paths:

| Path     | Role  |
| -------- | ----- |
| `/`      | 20    |
| `/api`   | 10    |
| `/admin` | 90    |

Most specific match **always wins**.

### Example

If a user has:

- `/` → role 20
- `/admin` → role 90

Accessing `/admin/users` resolves to `/admin` → requires role 90.

---

## Architecture

### Components

- `authstore` – manages users and permissions
- `sessionstore` – handles cookie-based sessions
- `enforcer` – evaluates policies and enforces access
- `tokenstore` *(planned)* – JWT-based API authentication

### Middleware Flow

```
Request
  ↓
[Authentication Middleware]
  ↓
[Authorization Middleware (Enforcer)]
  ↓
Your Handler
```

---

## API & Policy Overview

You can define access policies with:

```go
gg.Enforcer.SetPolicy("/admin", "*", models.RoleAdmin)
gg.Enforcer.SetPolicy("/admin/users", "GET", models.RoleSystemAdmin)
```

Each route can specify a required role per HTTP method, or use `"*"` to apply to all methods.

---

<!-- ## Examples

More usage examples and patterns can be found in the [`examples/`](./examples) folder.

--- -->

## License

`groundgo` is open source and licensed under the [MIT License](./LICENSE).

This permissive license allows commercial use, modification, distribution, and private use — while keeping attribution.

---

## Contributing

Contributions are welcome! Feel free to open an issue, suggest improvements, or submit a PR. For feature discussions, please use the [Discussions](https://github.com/Ryan-Har/groundgo/discussions) tab if enabled.

---

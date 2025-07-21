package groundgo

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/Ryan-Har/groundgo/pkg/access"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/Ryan-Har/groundgo/pkg/services"
	"github.com/Ryan-Har/groundgo/web/templates"
	"github.com/go-logr/logr"
)

type GroundGo struct {
	logger   logr.Logger
	config   *Config
	Services *services.Services
	Enforcer *access.Enforcer

	// Hold information to initialize services after configuration
	db               *sql.DB
	dbType           services.DBType
	router           access.Router
	sessionsInMemory bool // detertmines if the session store is held in memory only
}

type Option func(*GroundGo)

func WithLogger(l logr.Logger) Option {
	return func(g *GroundGo) {
		// Only set the logger if it's not a no-op logger, allowing for explicit Discard()
		// or if the current logger is Discard() (the default)
		if l.GetSink() != nil || g.logger.GetSink() == nil {
			g.logger = l
		}
	}
}

func WithSqliteDB(db *sql.DB) Option {
	return func(g *GroundGo) {
		g.db = db
		g.dbType = services.DBTypeSQLite
	}
}

func WithRouter(r access.Router) Option {
	return func(g *GroundGo) {
		g.router = r
	}
}

func WithInMemorySessionStore() Option {
	return func(g *GroundGo) {
		g.sessionsInMemory = true
	}
}

func New(opts ...Option) (*GroundGo, error) {
	gg := &GroundGo{
		logger: logr.Discard(), // default to no-op logger
	}

	for _, opt := range opts {
		opt(gg)
	}

	gg.logger.V(0).Info("starting groundgo")

	// load services now that logging is set
	gg.logger.V(0).Info("attempting to load services")
	gg.Services = services.New(gg.db, gg.dbType, gg.logger, gg.sessionsInMemory)

	// load enforcer
	gg.logger.V(0).Info("attempting to load enforcer")
	gg.Enforcer = access.NewEnforcer(gg.logger, gg.router, gg.Services.Auth, gg.Services.Session)

	// check if database is pingable
	gg.logger.V(0).Info("attempting ping of database")
	if err := gg.db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	if err := gg.Services.Auth.RunMigrations(); err != nil {
		return nil, fmt.Errorf("unable to run migrations: %w", err)
	}

	return gg, nil
}

type Config struct {
	//AllowSignup bool
	//SessionSecret string
	//JWTSecret string
	//TokenTTL time.Duration
	//CustomClaims map[string]any

	IncludeLoginSignupPages bool
}

func (g *GroundGo) SetDefaultRoutes() {
	g.Enforcer.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		content := templates.LoginPage()
		if err := templates.Layout("Login", content).Render(r.Context(), w); err != nil {
			g.logger.Error(err, "unable to GET /login")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	g.Enforcer.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		defer g.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			g.logger.Error(err, "parsing form from POST /login")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		g.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := g.Services.Auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				g.logger.Error(err, "returning login error from POST /login")
			}
			return
		}
		if !passwd.Authenticate(password, *user.PasswordHash) {
			if rendErr := templates.LoginError().Render(r.Context(), w); rendErr != nil {
				g.logger.Error(err, "returning login error from POST /login")
			}
			return
		}

		session, err := g.Services.Session.Create(r.Context(), user.ID)
		if err != nil {
			g.logger.Error(err, "creating session")
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})

	g.Enforcer.HandleFunc("GET /signup", func(w http.ResponseWriter, r *http.Request) {
		content := templates.SignupPage()
		if err := templates.Layout("Signup", content).Render(r.Context(), w); err != nil {
			g.logger.Error(err, "unable to GET /signup")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	g.Enforcer.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		defer g.logger.V(4).Info("Processed", "method", r.Method, "path", r.URL.Path, "remote_ip", r.RemoteAddr, "user_agent", r.UserAgent())

		if err := r.ParseForm(); err != nil {
			g.logger.Error(err, "parsing form from POST /signup")
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		g.logger.V(4).Info("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			if err := templates.SignupError("Passwords do not match").Render(r.Context(), w); err != nil {
				g.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		if exists, _ := g.Services.Auth.CheckEmailExists(r.Context(), email); exists {
			if err := templates.SignupError("Account already exists").Render(r.Context(), w); err != nil {
				g.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		user, err := g.Services.Auth.CreateUser(r.Context(), models.CreateUserParams{
			Email:    email,
			Password: &password,
			Role:     "user",
			Claims:   models.Claims{},
		})
		if err != nil {
			if err := templates.SignupError("Unable to create user, please try again later.").Render(r.Context(), w); err != nil {
				g.logger.Error(err, "returning signup error from POST /signup")
			}
			return
		}

		session, err := g.Services.Session.Create(r.Context(), user.ID)
		if err != nil {
			g.logger.Error(err, "creating session")
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HttpOnly: true,
			Secure:   false,
		})

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	})

	g.Enforcer.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		users, err := g.Services.Auth.ListAllUsers(r.Context())
		if err != nil {
			g.logger.Error(err, "unable to list users")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		content := templates.AdminPage(users)
		if err := templates.Layout("Admin", content).Render(r.Context(), w); err != nil {
			g.logger.Error(err, "unable to GET /admin")
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

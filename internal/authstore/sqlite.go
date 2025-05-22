package authstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/Ryan-Har/groundgo/database"
	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/transform"
	"github.com/go-logr/logr"
)

type sqliteAuthStore struct {
	db      *sql.DB
	queries sqliteDB.Queries
	log     logr.Logger
}

func (s *sqliteAuthStore) Ping() error {
	s.log.V(0).Info("attempting ping of database")
	return s.db.Ping()
}

func (s *sqliteAuthStore) RunMigrations() error {
	defer s.newTimingLogger(time.Now(), "ran database migrations")()
	s.log.V(0).Info("running auth database migrations")
	return database.RunSqliteMigrations(s.db)
}

// used to set the logger the auth store uses to log
func (s *sqliteAuthStore) SetLogger(logger logr.Logger) {
	s.log = logger
}

// newTimingLogger returns a function that, when deferred, logs the elapsed time at an info level.
// It initial fields that you want to include in the final log message.
func (s *sqliteAuthStore) newTimingLogger(start time.Time, msg string, initialFields ...any) func() {
	return func() {
		elapsed := time.Since(start)
		finalFields := append(initialFields, "duration", elapsed.String())
		s.log.V(3).Info(msg, finalFields...)
	}
}

func (s *sqliteAuthStore) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "CheckEmailExists", "args", map[string]any{"email": email})()
	i, err := s.queries.CheckEmailExists(ctx, email)
	return i != 0, err
}

func (s *sqliteAuthStore) CreateUser(ctx context.Context, args models.CreateUserParams) (models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "CreateUser", "args", map[string]any{"email": args.Email, "role": args.Role})()
	params, err := transform.ToSQLiteCreateUserParams(args)
	if err != nil {
		s.log.Error(err, "creating user")
		return models.User{}, err
	}
	sqlUser, err := s.queries.CreateUser(ctx, params)
	return transform.FromSQLiteUser(sqlUser), err
}

func (s *sqliteAuthStore) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByEmail", "args", map[string]any{"email": email})()
	sqlUser, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return models.User{}, err
	}
	return transform.FromSQLiteUser(sqlUser), nil
}

package authstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Ryan-Har/groundgo/database"
	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/transform"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
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

	// set the root to the provided role
	if args.Role.IsValid() {
		args.Claims.AddRole("/", models.Role(args.Role))
	} else {
		err := errors.New("invalid role provided")
		s.log.Error(err, "creating user")
		return models.User{}, err
	}

	params, err := transform.ToSQLiteCreateUserParams(args)
	if err != nil {
		s.log.Error(err, "creating user")
		return models.User{}, err
	}
	//generate UUID manually for sqlite
	params.ID = uuid.NewString()

	sqlUser, err := s.queries.CreateUser(ctx, params)
	if err != nil {
		s.log.Error(err, "creating user")
		return models.User{}, err
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return models.User{}, err
	}
	return user, nil
}

func (s *sqliteAuthStore) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByEmail", "args", map[string]any{"email": email})()
	sqlUser, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return models.User{}, err
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return models.User{}, err
	}
	return user, nil
}

func (s *sqliteAuthStore) GetUserByID(ctx context.Context, id uuid.UUID) (models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByID", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return models.User{}, errors.New("invalid id found")
	}

	sqlUser, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return models.User{}, err
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return models.User{}, err
	}
	return user, nil
}

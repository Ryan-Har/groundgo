package authstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
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

func (s *sqliteAuthStore) CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "CreateUser", "args", map[string]any{"email": args.Email, "role": args.Role})()

	// set the root to the provided role
	if args.Role.IsValid() {
		args.Claims.AddRole("/", models.Role(args.Role))
	} else {
		err := errors.New("invalid role provided")
		s.log.Error(err, "creating user")
		return nil, models.NewValidationError(err.Error())
	}

	params, err := transform.ToSQLiteCreateUserParams(args)
	if err != nil {
		s.log.Error(err, "creating user")
		return nil, models.NewTransformationError(err.Error())
	}
	//generate UUID manually for sqlite
	params.ID = uuid.NewString()

	sqlUser, err := s.queries.CreateUser(ctx, params)
	if err != nil {
		s.log.Error(err, "creating user")
		return nil, models.NewDatabaseError("failed to create user", err)
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return nil, models.NewTransformationError(err.Error())
	}
	return &user, nil
}

func (s *sqliteAuthStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByEmail", "args", map[string]any{"email": email})()
	sqlUser, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, models.NewDatabaseError("failed to get user by email", err)
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return nil, models.NewTransformationError(err.Error())
	}
	return &user, nil
}

func (s *sqliteAuthStore) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByID", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return nil, models.NewValidationError("id not set")
	}

	sqlUser, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return nil, models.NewDatabaseError("failed to get user by id", err)
	}
	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return nil, models.NewTransformationError(err.Error())
	}

	return &user, nil
}

func (s *sqliteAuthStore) GetUserByOAuth(ctx context.Context, args models.UserOAuthParams) (*models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "GetUserByOAuth", "args", args)()

	if args.OauthID == "" || args.OauthProvider == "" {
		msg := "params contain empty string"
		s.log.V(1).Info(msg, args)
		return nil, models.NewValidationError(msg)
	}

	params := transform.ToGetUserByOAuthParams(args)

	sqlUser, err := s.queries.GetUserByOAuth(ctx, params)
	if err != nil {
		return nil, models.NewDatabaseError("failed to get user by oauth", err)
	}

	user, err := transform.FromSQLiteUser(sqlUser)
	if err != nil {
		s.log.Error(err, "transforming user")
		return nil, models.NewTransformationError(err.Error())
	}
	return &user, nil
}

func (s *sqliteAuthStore) ListAllUsers(ctx context.Context) ([]*models.User, error) {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "ListAllUsers")()

	var users []*models.User

	sqlUsers, err := s.queries.ListAllUsers(ctx)
	if err != nil {
		return users, models.NewDatabaseError("failed to list all users", err)
	}

	var errs []error

	for _, sqlUser := range sqlUsers {
		user, err := transform.FromSQLiteUser(sqlUser)
		if err != nil {
			errs = append(errs, models.NewTransformationError(err.Error()))
			continue
		}
		users = append(users, &user)
	}

	if len(errs) > 0 {
		// Return partial results with joined transformation errors
		return users, errors.Join(errs...)
	}

	return users, nil
}

func (s *sqliteAuthStore) SoftDeleteUser(ctx context.Context, id uuid.UUID) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "SoftDeleteUser", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	err := s.queries.UpdateUserIsActive(ctx, sqliteDB.UpdateUserIsActiveParams{
		ID:       id.String(),
		IsActive: false,
	})

	if err != nil {
		return models.NewDatabaseError("failed to soft delete user", err)
	}
	return nil
}

func (s *sqliteAuthStore) RestoreUser(ctx context.Context, id uuid.UUID) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "RestoreUser", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	err := s.queries.UpdateUserIsActive(ctx, sqliteDB.UpdateUserIsActiveParams{
		ID:       id.String(),
		IsActive: true,
	})

	if err != nil {
		return models.NewDatabaseError("failed to restore user", err)
	}
	return nil
}

func (s *sqliteAuthStore) HardDeleteUser(ctx context.Context, id uuid.UUID) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "HardDeleteUser", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	err := s.queries.DeleteUser(ctx, id.String())

	if err != nil {
		return models.NewDatabaseError("failed to hard delete user", err)
	}
	return nil
}

// TODO
func (s *sqliteAuthStore) UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "UpdateUserRole", "args", map[string]any{"ID": id.String(), "role": role.String()})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	user, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return models.NewDatabaseError("failed to fetch user for role update", err)
	}

	userClaims, err := transform.ParseClaims(user.Claims)
	if err != nil {
		return models.NewTransformationError(err.Error())
	}

	// Update the root claim ("/") to match the new role
	userClaims["/"] = role

	// Marshal updated claims
	claimsStr, err := transform.SerializeClaims(userClaims)
	if err != nil {
		return models.NewTransformationError(err.Error())
	}

	// Update the user's role and claims
	err = s.queries.UpdateUserRoleAndClaims(ctx, sqliteDB.UpdateUserRoleAndClaimsParams{
		ID:     id.String(),
		Role:   role.String(),
		Claims: claimsStr,
	})
	if err != nil {
		return models.NewDatabaseError("failed to update user role", err)
	}

	return nil
}

func (s *sqliteAuthStore) UpdateUserClaims(ctx context.Context, id uuid.UUID, claims models.Claims) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "UpdateUserClaims", "args", map[string]any{"ID": id.String(), "claims": claims})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	user, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return models.NewDatabaseError("failed to fetch user for claim update", err)
	}

	// role must be updated if the root claim is. If now, the root claim should be added.
	_, exists := claims["/"]
	if !exists {
		claims["/"] = models.Role(user.Role)
	}

	claimsStr, err := transform.SerializeClaims(claims)
	if err != nil {
		return models.NewTransformationError(err.Error())
	}

	// Update the user's role and claims
	err = s.queries.UpdateUserRoleAndClaims(ctx, sqliteDB.UpdateUserRoleAndClaimsParams{
		ID:     id.String(),
		Role:   claims["/"].String(),
		Claims: claimsStr,
	})

	if err != nil {
		return models.NewDatabaseError("failed to update user claims", err)
	}

	return nil
}

func (s *sqliteAuthStore) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	defer s.newTimingLogger(time.Now(), "executed sql query", "method", "UpdateUserPassword", "args", map[string]any{"ID": id.String()})()

	if id == uuid.Nil {
		return models.NewValidationError("id not set")
	}

	hashed, err := passwd.HashPassword(password)
	if err != nil {
		return models.NewTransformationError("failed to hash password")
	}

	err = s.queries.UpdateUserPassword(ctx, sqliteDB.UpdateUserPasswordParams{
		ID:           id.String(),
		PasswordHash: &hashed,
	})
	if err != nil {
		return models.NewDatabaseError("failed to update password", err)
	}
	return nil
}

package authstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db"
	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/internal/logutil"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

type sqliteAuthStore struct {
	db      *sql.DB
	queries sqliteDB.Queries
	log     *slog.Logger
}

func (s *sqliteAuthStore) Ping() error {
	return s.db.Ping()
}

func (s *sqliteAuthStore) CheckEmailExists(ctx context.Context, email string) (bool, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "CheckEmailExists")()
	i, err := s.queries.CheckEmailExists(ctx, email)
	return i != 0, err
}

func (s *sqliteAuthStore) CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "CreateUser")()
	errMsg := "failed to create user"

	// set the root to the provided role
	if args.Role.IsValid() {
		args.Claims.AddRole("/", models.Role(args.Role))
	} else {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewValidationError(fmt.Sprintf("invalid role: %s", args.Role.String())),
		)
	}

	params, err := sqliteDB.CreateUserParamsFromModel(args)
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}
	//generate UUID manually for sqlite
	params.ID = uuid.NewString()

	sqlUser, err := s.queries.CreateUser(ctx, params)
	if err != nil {
		_, err := db.WrapErrorIfDuplciateConstraint(err)
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err))
	}
	user, err := sqlUser.ToUserModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}
	return &user, nil
}

func (s *sqliteAuthStore) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "GetUserByEmail")()
	errMsg := "failed to get user by email"

	sqlUser, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	user, err := sqlUser.ToUserModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}
	return &user, nil
}

func (s *sqliteAuthStore) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "GetUserByID", "ID", id.String())()
	errMsg := "failed to get user by id"

	if id == uuid.Nil {
		return nil, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	sqlUser, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return nil, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	user, err := sqlUser.ToUserModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}

	return &user, nil
}

func (s *sqliteAuthStore) GetUserByOAuth(ctx context.Context, args models.UserOAuthParams) (*models.User, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "GetUserByOAuth")()
	errMsg := "failed to get user by oauth"

	if args.OauthID == "" || args.OauthProvider == "" {
		return nil, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id or provider not set"),
		)
	}

	params := sqliteDB.GetUserByOAuthParamsFromModel(args)

	sqlUser, err := s.queries.GetUserByOAuth(ctx, params)
	if err != nil {
		return nil, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	user, err := sqlUser.ToUserModel()
	if err != nil {
		return nil, logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}
	return &user, nil
}

func (s *sqliteAuthStore) ListAllUsers(ctx context.Context) ([]*models.User, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "ListAllUsers")()
	errMsg := "failed to list all users"

	var users []*models.User

	sqlUsers, err := s.queries.ListAllUsers(ctx)
	if err != nil {
		return users, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	var errs []error

	for _, sqlUser := range sqlUsers {
		user, err := sqlUser.ToUserModel()
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

func (s *sqliteAuthStore) ListUsersPaginatedWithRoleFilter(ctx context.Context, args models.GetPaginatedUsersParams) ([]*models.User, models.PaginationMeta, error) {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "ListUsersPaginatedWithRoleFilter")()
	errMsg := "failed to list all users"

	if args.Page < 1 {
		args.Page = 1
	}
	if args.Limit < 1 {
		args.Limit = 20
	}

	offset := int64((args.Page - 1) * args.Limit)

	params := sqliteDB.ListUsersPaginatedWithTotalParams{
		Limit:  int64(args.Limit),
		Offset: offset,
		Role:   args.Role,
	}

	pagData := models.PaginationMeta{
		Limit:      args.Limit,
		Page:       args.Page,
		Total:      0,
		TotalPages: 0,
	}

	pagUsers, err := s.queries.ListUsersPaginatedWithTotal(ctx, params)
	if err != nil {
		return nil, pagData, logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	// force NoRows error if there's no users
	if len(pagUsers) == 0 {
		return []*models.User{}, pagData, nil
	}

	// Get total from first row (all rows have the same total due to window function)
	pagData.Total = int(pagUsers[0].Total)
	pagData.TotalPages = int(math.Ceil(float64(pagData.Total) / float64(args.Limit)))

	var errs []error
	users := make([]*models.User, 0, len(pagUsers))

	for _, pagUser := range pagUsers {
		user, err := pagUser.ToUserModel()
		if err != nil {
			errs = append(errs, models.NewTransformationError(err.Error()))
			continue
		}
		users = append(users, &user)
	}

	if len(errs) > 0 {
		// Return partial results with joined transformation errors
		return users, pagData, errors.Join(errs...)
	}

	return users, pagData, nil
}

func (s *sqliteAuthStore) SoftDeleteUser(ctx context.Context, id uuid.UUID) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "SoftDeleteUser", "ID", id.String())()
	errMsg := "failed to soft delete user"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	err := s.queries.UpdateUserIsActive(ctx, sqliteDB.UpdateUserIsActiveParams{
		ID:       id.String(),
		IsActive: false,
	})

	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	return nil
}

func (s *sqliteAuthStore) RestoreUser(ctx context.Context, id uuid.UUID) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "RestoreUser", "ID", id.String())()
	errMsg := "failed to restore user"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	err := s.queries.UpdateUserIsActive(ctx, sqliteDB.UpdateUserIsActiveParams{
		ID:       id.String(),
		IsActive: true,
	})

	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	return nil
}

func (s *sqliteAuthStore) HardDeleteUser(ctx context.Context, id uuid.UUID) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "HardDeleteUser", "ID", id.String())()
	errMsg := "failed to hard delete user"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	err := s.queries.DeleteUser(ctx, id.String())

	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	return nil
}

// TODO
func (s *sqliteAuthStore) UpdateUserRole(ctx context.Context, id uuid.UUID, role models.Role) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "UpdateUserRole", "ID", id.String())()
	errMsg := "failed to update user role"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	user, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	userClaims, err := sqliteDB.ParseClaims(user.Claims)
	if err != nil {
		return logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}

	// Update the root claim ("/") to match the new role
	userClaims["/"] = role

	// Marshal updated claims
	claimsStr, err := sqliteDB.SerializeClaims(userClaims)
	if err != nil {
		return logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}

	// Update the user's role and claims
	err = s.queries.UpdateUserRoleAndClaims(ctx, sqliteDB.UpdateUserRoleAndClaimsParams{
		ID:     id.String(),
		Role:   role.String(),
		Claims: claimsStr,
	})
	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	return nil
}

func (s *sqliteAuthStore) UpdateUserClaims(ctx context.Context, id uuid.UUID, claims models.Claims) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "UpdateUserClaims", "ID", id.String())()
	errMsg := "failed to update user claims"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	user, err := s.queries.GetUserByID(ctx, id.String())
	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	// role must be updated if the root claim is. If not, the root claim should be added to allow for role based access
	_, exists := claims["/"]
	if !exists {
		claims["/"] = models.Role(user.Role)
	}

	claimsStr, err := sqliteDB.SerializeClaims(claims)
	if err != nil {
		return logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}

	// Update the user's role and claims
	err = s.queries.UpdateUserRoleAndClaims(ctx, sqliteDB.UpdateUserRoleAndClaimsParams{
		ID:     id.String(),
		Role:   claims["/"].String(),
		Claims: claimsStr,
	})

	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}

	return nil
}

func (s *sqliteAuthStore) UpdateUserPassword(ctx context.Context, id uuid.UUID, password string) error {
	defer logutil.NewTimingLogger(s.log, time.Now(), "executed sql query", "method", "UpdateUserPassword", "ID", id.String())()
	errMsg := "failed to update user password"

	if id == uuid.Nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewValidationError("id not set"),
		)
	}

	hashed, err := passwd.HashPassword(password)
	if err != nil {
		return logutil.LogAndWrapErr(s.log, errMsg,
			models.NewTransformationError(err.Error()),
		)
	}

	err = s.queries.UpdateUserPassword(ctx, sqliteDB.UpdateUserPasswordParams{
		ID:           id.String(),
		PasswordHash: &hashed,
	})
	if err != nil {
		return logutil.DebugAndWrapErr(s.log, errMsg,
			models.NewDatabaseError(err),
		)
	}
	return nil
}

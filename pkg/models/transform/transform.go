package transform

import (
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
)

func FromSQLiteUser(args sqliteDB.User) models.User {
	return models.User{
		ID:            args.ID,
		Email:         args.Email,
		PasswordHash:  args.PasswordHash,
		Role:          args.Role,
		Claims:        args.Claims,
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
		CreatedAt:     time.Unix(args.CreatedAt, 0),
		UpdatedAt:     time.Unix(args.UpdatedAt, 0),
		IsActive:      args.IsActive,
	}
}

func ToSQLiteUser(args models.User) sqliteDB.User {
	return sqliteDB.User{
		ID:            args.ID,
		Email:         args.Email,
		PasswordHash:  args.PasswordHash,
		Role:          args.Role,
		Claims:        args.Claims,
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
		CreatedAt:     args.CreatedAt.Unix(),
		UpdatedAt:     args.UpdatedAt.Unix(),
		IsActive:      args.IsActive,
	}
}

func ToSQLiteCreateUserParams(args models.CreateUserParams) (sqliteDB.CreateUserParams, error) {
	params := sqliteDB.CreateUserParams{
		Email:         args.Email,
		Role:          args.Role,
		Claims:        args.Claims,
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
	}

	// passwords can be nil when using Oauth
	if args.Password != nil {
		hashed, err := passwd.HashPassword(*args.Password)
		if err != nil {
			return params, err
		}
		params.PasswordHash = &hashed
	}
	return params, nil
}

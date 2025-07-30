// Package transform contains internal helpers for converting between database-specific
// representations (e.g. sqliteDB.User) and the shared models.User domain type.
//
// This package is not intended for use outside the application layer.
package transform

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Ryan-Har/groundgo/internal/db/sqliteDB"
	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

func FromSQLiteUser(args sqliteDB.User) (models.User, error) {
	usr := models.User{
		Email:         args.Email,
		PasswordHash:  args.PasswordHash,
		Role:          models.Role(args.Role),
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
		CreatedAt:     time.Unix(args.CreatedAt, 0),
		UpdatedAt:     time.Unix(args.UpdatedAt, 0),
		IsActive:      args.IsActive,
	}

	usrID, err := uuid.Parse(args.ID)
	if err != nil {
		return models.User{}, err
	}

	usrClaims, err := ParseClaims(args.Claims)
	if err != nil {
		return models.User{}, err
	}
	usr.ID = usrID
	usr.Claims = usrClaims
	return usr, nil
}

func ToSQLiteUser(args models.User) (sqliteDB.User, error) {
	usr := sqliteDB.User{
		ID:            args.ID.String(),
		Email:         args.Email,
		PasswordHash:  args.PasswordHash,
		Role:          args.Role.String(),
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
		CreatedAt:     args.CreatedAt.Unix(),
		UpdatedAt:     args.UpdatedAt.Unix(),
		IsActive:      args.IsActive,
	}

	claims, err := SerializeClaims(args.Claims)
	if err != nil {
		return sqliteDB.User{}, err
	}
	usr.Claims = claims
	return usr, nil
}

func ToSQLiteCreateUserParams(args models.CreateUserParams) (sqliteDB.CreateUserParams, error) {
	params := sqliteDB.CreateUserParams{
		Email:         args.Email,
		Role:          args.Role.String(),
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
	}

	claims, err := SerializeClaims(args.Claims)
	if err != nil {
		return sqliteDB.CreateUserParams{}, err
	}
	params.Claims = claims

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

func SerializeClaims(claims models.Claims) (*string, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	data, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize claims: %w", err)
	}
	jsonStr := string(data)
	return &jsonStr, nil
}

func ParseClaims(claimsJSON *string) (models.Claims, error) {
	if claimsJSON == nil || *claimsJSON == "" {
		return make(map[string]models.Role), nil
	}

	var claims map[string]models.Role
	err := json.Unmarshal([]byte(*claimsJSON), &claims)
	if err != nil {
		return nil, fmt.Errorf("invalid claims JSON: %w", err)
	}

	return claims, nil
}

func ToGetUserByOAuthParams(args models.UserOAuthParams) sqliteDB.GetUserByOAuthParams {
	var providerPtr, idPtr *string

	if args.OauthProvider != "" {
		providerPtr = &args.OauthProvider
	}
	if args.OauthID != "" {
		idPtr = &args.OauthID
	}

	return sqliteDB.GetUserByOAuthParams{
		OauthProvider: providerPtr,
		OauthID:       idPtr,
	}
}

func ToSQLiteCreateSessionParams(args models.Session) sqliteDB.CreateSessionParams {
	return sqliteDB.CreateSessionParams{
		ID:        args.ID,
		UserID:    args.UserID.String(),
		ExpiresAt: args.ExpiresAt.Unix(),
		IpAddress: args.IpAddress,
		UserAgent: args.UserAgent,
	}
}

func FromSQLiteSession(args sqliteDB.Session) (models.Session, error) {
	sesh := models.Session{
		ID:        args.ID,
		ExpiresAt: time.Unix(args.ExpiresAt, 0),
		IpAddress: args.IpAddress,
		UserAgent: args.UserAgent,
		CreatedAt: time.Unix(args.CreatedAt, 0),
	}

	usrID, err := ParseUUIDAllowEmpty(args.UserID)
	if err != nil {
		return models.Session{}, err
	}

	sesh.UserID = usrID
	return sesh, nil
}

func ParseUUIDAllowEmpty(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, nil // treat empty string as nil UUID
	}

	return uuid.Parse(s) // validate and parse all others
}

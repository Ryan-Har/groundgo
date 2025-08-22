package sqliteDB

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

func (u *User) ToUserModel() (models.User, error) {
	usr := models.User{
		Email:         u.Email,
		PasswordHash:  u.PasswordHash,
		Role:          models.Role(u.Role),
		OauthProvider: u.OauthProvider,
		OauthID:       u.OauthID,
		CreatedAt:     time.Unix(u.CreatedAt, 0),
		UpdatedAt:     time.Unix(u.UpdatedAt, 0),
		IsActive:      u.IsActive,
	}

	usrID, err := uuid.Parse(u.ID)
	if err != nil {
		return models.User{}, err
	}

	usrClaims, err := ParseClaims(u.Claims)
	if err != nil {
		return models.User{}, err
	}
	usrClaims["/"] = usr.Role
	usr.ID = usrID
	usr.Claims = usrClaims
	return usr, nil
}

func (u *ListUsersPaginatedWithTotalRow) ToUserModel() (models.User, error) {
	usr := models.User{
		Email:         u.Email,
		PasswordHash:  u.PasswordHash,
		Role:          models.Role(u.Role),
		OauthProvider: u.OauthProvider,
		OauthID:       u.OauthID,
		CreatedAt:     time.Unix(u.CreatedAt, 0),
		UpdatedAt:     time.Unix(u.UpdatedAt, 0),
		IsActive:      u.IsActive,
	}

	usrID, err := uuid.Parse(u.ID)
	if err != nil {
		return models.User{}, err
	}

	usrClaims, err := ParseClaims(u.Claims)
	if err != nil {
		return models.User{}, err
	}
	usrClaims["/"] = usr.Role
	usr.ID = usrID
	usr.Claims = usrClaims
	return usr, nil
}

func UserFromModel(args models.User) (User, error) {
	usr := User{
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
		return User{}, err
	}
	usr.Claims = claims
	return usr, nil
}

func CreateUserParamsFromModel(args models.CreateUserParams) (CreateUserParams, error) {
	params := CreateUserParams{
		Email:         args.Email,
		Role:          args.Role.String(),
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
	}

	claims, err := SerializeClaims(args.Claims)
	if err != nil {
		return CreateUserParams{}, err
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

func GetUserByOAuthParamsFromModel(args models.UserOAuthParams) GetUserByOAuthParams {
	var providerPtr, idPtr *string

	if args.OauthProvider != "" {
		providerPtr = &args.OauthProvider
	}
	if args.OauthID != "" {
		idPtr = &args.OauthID
	}

	return GetUserByOAuthParams{
		OauthProvider: providerPtr,
		OauthID:       idPtr,
	}
}

func CreateSessionParamsFromModel(args models.Session) CreateSessionParams {
	return CreateSessionParams{
		ID:        args.ID,
		UserID:    args.UserID.String(),
		ExpiresAt: args.ExpiresAt.Unix(),
		IpAddress: args.IpAddress,
		UserAgent: args.UserAgent,
	}
}

func (s *Session) ToSessionModel() (models.Session, error) {
	sesh := models.Session{
		ID:        s.ID,
		ExpiresAt: time.Unix(s.ExpiresAt, 0),
		IpAddress: s.IpAddress,
		UserAgent: s.UserAgent,
		CreatedAt: time.Unix(s.CreatedAt, 0),
	}

	usrID, err := ParseUUIDAllowEmpty(s.UserID)
	if err != nil {
		return models.Session{}, err
	}

	sesh.UserID = usrID
	return sesh, nil
}

func UpdateUserByIDParamsFromModel(args models.UpdateUserByIDParams) (UpdateUserByIDParams, error) {
	params := UpdateUserByIDParams{
		Email:         args.Email,
		OauthProvider: args.OauthProvider,
		OauthID:       args.OauthID,
		IsActive:      args.IsActive,
	}

	if args.ID == uuid.Nil {
		return UpdateUserByIDParams{}, errors.New("provided id is nil")
	}
	params.ID = args.ID.String()

	if args.Password != nil && !passwd.IsHashed(*args.Password) {
		return UpdateUserByIDParams{}, errors.New("provided password is not yet hashed")
	}
	params.PasswordHash = args.Password

	if args.Claims != nil {
		claims, err := SerializeClaims(*args.Claims)
		if err != nil {
			return UpdateUserByIDParams{}, err
		}
		params.Claims = claims
	}

	if args.Role != nil {
		params.Role = (*string)(args.Role)
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

func ParseUUIDAllowEmpty(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, nil // treat empty string as nil UUID
	}

	return uuid.Parse(s) // validate and parse all others
}

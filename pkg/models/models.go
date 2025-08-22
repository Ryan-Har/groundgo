package models

import (
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	"github.com/google/uuid"
)

type CreateUserParams struct {
	Email         string  `json:"email"`
	Password      *string `json:"password"`
	Role          Role    `json:"role"`
	Claims        Claims  `json:"claims"`
	OauthProvider *string `json:"oauthProvider"`
	OauthID       *string `json:"oauthId"`
}

func (c *CreateUserParams) Validate() error {

	if c.Email == "" {
		return NewValidationError("email is required")
	}
	if _, err := mail.ParseAddress(c.Email); err != nil {
		return NewValidationError(fmt.Sprintf("email address %s is not a valid RFC 5322 format", c.Email))
	}

	if c.Password == nil {
		return NewValidationError("password is required")
	}
	return nil
}

type User struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	PasswordHash  *string   `json:"-"`
	Role          Role      `json:"role"`
	Claims        Claims    `json:"claims"`
	OauthProvider *string   `json:"oauthProvider"`
	OauthID       *string   `json:"oauthId"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	IsActive      bool      `json:"isActive"`
}

// UpdateUserByIDParams is a struct for updating a user
// Everything is intentionally a pointer to allow for Coalescing at the db level
type UpdateUserByIDParams struct {
	ID            uuid.UUID `json:"id"`
	Email         *string   `json:"email"`
	Password      *string   `json:"-"`
	Role          *Role     `json:"role"`
	Claims        *Claims   `json:"claims"`
	OauthProvider *string   `json:"oauthProvider"`
	OauthID       *string   `json:"oauthId"`
	IsActive      *bool     `json:"isActive"`
}

// Verify performs validation and transformation on the UpdateUserByIDParams struct.
// It ensures required fields are present, validates input formats, and hashes the password if provided.
func (u *UpdateUserByIDParams) Verify() error {
	if u.ID == uuid.Nil {
		return NewValidationError("id not set")
	}

	if u.Email != nil {
		if _, err := mail.ParseAddress(*u.Email); err != nil {
			return NewValidationError(fmt.Sprintf("email address %s is not a valid RFC 5322 format", *u.Email))
		}
	}

	// remove any root claims that may exist, The root claim is effectively the role.
	if u.Claims != nil {
		delete(*u.Claims, "/")
	}

	if u.Password != nil {
		hashed, err := passwd.HashPassword(*u.Password)
		if err != nil {
			return NewTransformationError(err.Error())
		}
		u.Password = &hashed
	}

	if u.OauthID != nil || u.OauthProvider != nil {
		return fmt.Errorf("oauth not yet implemented")
	}

	return nil
}

type GetPaginatedUsersParams struct {
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
	Role  *Role `json:"role"`
}

func (p *GetPaginatedUsersParams) Validate() error {
	if p.Page < 1 {
		return errors.New("page must be greater than 0")
	}
	if p.Limit > 100 || p.Limit < 1 {
		return errors.New("limit must be between 1 and 100")
	}
	return nil
}

type PaginationMeta struct {
	Limit      int `json:"limit"`
	Page       int `json:"page"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}

func (u *User) EnsureRootClaim() {
	u.Claims.AddRole("/", u.Role)
}

type UserOAuthParams struct {
	OauthProvider string `json:"oauthProvider"`
	OauthID       string `json:"oauthId"`
}

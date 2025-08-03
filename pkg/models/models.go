package models

import (
	"time"

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

func (u *User) EnsureRootClaim() {
	u.Claims.AddRole("/", u.Role)
}

type UserOAuthParams struct {
	OauthProvider string `json:"oauthProvider"`
	OauthID       string `json:"oauthId"`
}

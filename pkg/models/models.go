package models

import (
	"time"
)

type CreateUserParams struct {
	Email         string  `json:"email"`
	Password      *string `json:"password"`
	Role          string  `json:"role"`
	Claims        *string `json:"claims"`
	OauthProvider *string `json:"oauthProvider"`
	OauthID       *string `json:"oauthId"`
}

type User struct {
	ID            int64     `json:"id"`
	Email         string    `json:"email"`
	PasswordHash  *string   `json:"passwordHash"`
	Role          string    `json:"role"`
	Claims        *string   `json:"claims"`
	OauthProvider *string   `json:"oauthProvider"`
	OauthID       *string   `json:"oauthId"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	IsActive      bool      `json:"isActive"`
}

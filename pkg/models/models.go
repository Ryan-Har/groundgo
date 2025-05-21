package models

type CreateUserParams struct {
	Email         string  `json:"email"`
	Password      *string `json:"password"`
	Role          string  `json:"role"`
	Claims        *string `json:"claims"`
	OauthProvider *string `json:"oauthProvider"`
	OauthID       *string `json:"oauthId"`
}

type User struct {
	ID            int64   `json:"id"`
	Email         string  `json:"email"`
	PasswordHash  *string `json:"passwordHash"`
	Role          string  `json:"role"`
	Claims        *string `json:"claims"`
	OauthProvider *string `json:"oauthProvider"`
	OauthID       *string `json:"oauthId"`
	CreatedAt     int64   `json:"createdAt"`
	UpdatedAt     int64   `json:"updatedAt"`
	IsActive      bool    `json:"isActive"`
}

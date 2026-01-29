package workflow

import (
	"context"
	"testing"

	"github.com/Ryan-Har/groundgo/pkg/models"
)

func TestUserFromContext(t *testing.T) {
	user := models.NewGuestUser()

	tests := []struct {
		name   string
		ctx    context.Context
		want   *models.User
		wantOk bool
	}{
		{"user present", ContextWithUser(context.Background(), user), user, true},
		{"user missing", context.Background(), nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := UserFromContext(tt.ctx)
			if ok != tt.wantOk {
				t.Errorf("UserFromContext() ok = %v, want %v", ok, tt.wantOk)
			}
			if got != tt.want {
				t.Errorf("UserFromContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJWTFromContext(t *testing.T) {
	token := "jwt-token"

	tests := []struct {
		name   string
		ctx    context.Context
		want   string
		wantOk bool
	}{
		{"jwt present", ContextWithJWT(context.Background(), token), token, true},
		{"jwt missing", context.Background(), "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := JWTFromContext(tt.ctx)
			if ok != tt.wantOk {
				t.Errorf("JWTFromContext() ok = %v, want %v", ok, tt.wantOk)
			}
			if got != tt.want {
				t.Errorf("JWTFromContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContextWithUserAndJWT(t *testing.T) {
	user := models.NewGuestUser()
	token := "token-123"

	ctx := ContextWithUserAndJWT(context.Background(), user, token)

	t.Run("user and jwt present", func(t *testing.T) {
		gotUser, okUser := UserFromContext(ctx)
		if !okUser || gotUser != user {
			t.Errorf("UserFromContext() = %v, ok = %v; want %v, true", gotUser, okUser, user)
		}

		gotJWT, okJWT := JWTFromContext(ctx)
		if !okJWT || gotJWT != token {
			t.Errorf("JWTFromContext() = %v, ok = %v; want %v, true", gotJWT, okJWT, token)
		}
	})
}

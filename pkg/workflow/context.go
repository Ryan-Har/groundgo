package workflow

import (
	"context"

	"github.com/Ryan-Har/groundgo/pkg/models"
)

type contextKey string

const (
	userContextKey contextKey = "user"
	jwtContextKey  contextKey = "jwt"
)

func UserFromContext(ctx context.Context) (*models.User, bool) {
	user, ok := ctx.Value(userContextKey).(*models.User)
	return user, ok
}

func JWTFromContext(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(jwtContextKey).(string)
	return user, ok
}

func ContextWithUser(ctx context.Context, user *models.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func ContextWithJWT(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, jwtContextKey, token)
}

func ContextWithUserAndJWT(ctx context.Context, user *models.User, token string) context.Context {
	ctx = ContextWithUser(ctx, user)
	return ContextWithJWT(ctx, token)
}

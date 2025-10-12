package webmodels

import (
	"html/template"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
)

type ErrorMessage string

type SignupError struct {
	ErrorMessage
}

// used with admin_page template
type AdminPageCtx struct {
	StatsCtx AdminPageStatisticsCtx
	TableCtx AdminPageUserTableCtx
}

// used with admin_statistics_component partial
type AdminPageStatisticsCtx struct {
	XData template.JS
}

// used with admin_page_user_table partial
type AdminPageUserTableCtx struct {
	RowCtxs []AdminPageUserTableRowCtx
}

// used with admin_page_user_table_row partial
type AdminPageUserTableRowCtx struct {
	ID        string
	Email     string
	IsActive  bool
	Claims    []string
	UpdatedAt string
	CreatedAt string
}

func BuildAdminPageCtx(users []*models.User) AdminPageCtx {
	return AdminPageCtx{
		StatsCtx: BuildAdminPageStatisticsCtx(users),
		TableCtx: BuildAdminPageTableUserTableCtx(users),
	}
}

func BuildAdminPageStatisticsCtx(users []*models.User) AdminPageStatisticsCtx {
	return AdminPageStatisticsCtx{
		XData: adminPageStatisticsxData(users),
	}
}

func BuildAdminPageTableUserTableCtx(users []*models.User) AdminPageUserTableCtx {
	rowCtxs := make([]AdminPageUserTableRowCtx, len(users))
	for i, user := range users {
		rowCtxs[i] = BuildAdminPageUserTableRowCtx(user)
	}
	return AdminPageUserTableCtx{
		RowCtxs: rowCtxs,
	}
}

func BuildAdminPageUserTableRowCtx(user *models.User) AdminPageUserTableRowCtx {
	return AdminPageUserTableRowCtx{
		ID:        user.ID.String(),
		Email:     user.Email,
		IsActive:  user.IsActive,
		Claims:    user.Claims.AsSlice(),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}
}

type AdminPageUserTableRowEditCtx struct {
	XData    template.JS
	ID       string
	Email    string
	IsActive bool
}

func BuildAdminPageUserTableRowEditCtx(user *models.User) AdminPageUserTableRowEditCtx {
	return AdminPageUserTableRowEditCtx{
		ID:       user.ID.String(),
		Email:    user.Email,
		IsActive: user.IsActive,
		XData:    userRowEditPartialxData(user),
	}
}

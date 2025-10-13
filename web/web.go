package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Ryan-Har/groundgo/pkg/models"
	"github.com/Ryan-Har/groundgo/pkg/models/passwd"
	webmodels "github.com/Ryan-Har/groundgo/web/models"
	"github.com/google/uuid"
)

//go:embed templates/**/*.go.tpl
var templateFiles embed.FS

// maybe static
////go:embed static/*
// var staticFiles embed.FS

type Handler struct {
	auth    auth
	session session
	cookie  cookie
	log     *slog.Logger
	tmpl    *templateEngine
}

func New(logger *slog.Logger, auth auth, session session, cookie cookie) *Handler {
	funcMap := template.FuncMap{
		"eq":  func(a, b any) bool { return a == b },
		"mod": func(a, b int) int { return a % b },
	}

	t := template.Must(
		template.New("").Funcs(funcMap).ParseFS(templateFiles, "templates/**/*.go.tpl"),
	)

	tmpl := templateEngine{
		tmpl: t,
		log:  logger,
	}

	return &Handler{
		auth:    auth,
		session: session,
		cookie:  cookie,
		log:     logger,
		tmpl:    &tmpl,
	}
}

type auth interface {
	ListAllUsers(ctx context.Context) ([]*models.User, error)
	CheckEmailExists(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, args models.CreateUserParams) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	UpdateUserByID(ctx context.Context, args models.UpdateUserByIDParams) (*models.User, error)
	HardDeleteUser(ctx context.Context, id uuid.UUID) error
	SoftDeleteUser(ctx context.Context, id uuid.UUID) error
	RestoreUser(ctx context.Context, id uuid.UUID) error
}

type session interface {
	Create(ctx context.Context, userID uuid.UUID) (*models.Session, error)
}

type cookie interface {
	SetUserSessionCookie(w http.ResponseWriter, value string, customExpires *time.Time) error
}

type templateEngine struct {
	tmpl *template.Template
	log  *slog.Logger
}

// Render renders any template to the http.ResponseWriter with standard logging messages.
func (t *templateEngine) Render(w http.ResponseWriter, name string, data any) {
	err := t.tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		t.log.Error("render template", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// RenderPage renders any page to the http.ResponseWriter with standard logging messages.
// It accepts the http.ResponseWriter, the pageName (name of the template), data (the context) and the title of the page.
func (t *templateEngine) RenderPage(w http.ResponseWriter, pageName string, data any, title string) {
	var buf bytes.Buffer

	// Render the page template into a buffer
	if err := t.tmpl.ExecuteTemplate(&buf, pageName, data); err != nil {
		t.log.Error("render page template", "name", pageName, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Wrap the page content into the layout
	layoutData := struct {
		Title   string
		Content template.HTML
	}{
		Title:   title,
		Content: template.HTML(buf.String()),
	}

	if err := t.tmpl.ExecuteTemplate(w, "base", layoutData); err != nil {
		t.log.Error("render layout template", "name", "base", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) HandleLoginGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.tmpl.RenderPage(w, "login_page", nil, "Login")
	}
}

func (h *Handler) HandleLoginPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			h.log.Error("parsing form from POST /login", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")

		h.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		user, err := h.auth.GetUserByEmail(r.Context(), email)
		if err != nil || user.PasswordHash == nil || !user.IsActive ||
			!passwd.Authenticate(password, *user.PasswordHash) {
			h.tmpl.Render(w, "login_error", nil)
			return
		}

		session, err := h.session.Create(r.Context(), user.ID)
		if err != nil {
			h.log.Error("creating session", "err", err)
			return
		}

		if err := h.cookie.SetUserSessionCookie(w, session.ID, &session.ExpiresAt); err != nil {
			h.log.Error("failed to set user session cookie", "err", err)
			return
		}

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) HandleSignupGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.tmpl.RenderPage(w, "signup_page", nil, "Signup")
	}
}

func (h *Handler) HandleSignupPost() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			h.log.Error("parsing form from POST /signup", "err", err)
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")

		h.log.Debug("form parsed", "method", r.Method, "path", r.URL.Path)
		if password != confirm {
			h.tmpl.Render(w, "signup_error", webmodels.SignupError{ErrorMessage: "Passwords do not match"})
			return
		}

		if exists, _ := h.auth.CheckEmailExists(r.Context(), email); exists {
			h.tmpl.Render(w, "signup_error", webmodels.SignupError{ErrorMessage: "Account already exists"})
			return
		}

		user, err := h.auth.CreateUser(r.Context(), models.CreateUserParams{
			Email:    email,
			Password: &password,
			Role:     "user",
			Claims:   models.Claims{},
		})
		if err != nil {
			h.tmpl.Render(w, "signup_error", webmodels.SignupError{ErrorMessage: "Unable to create user, please try again later"})
			return
		}

		session, err := h.session.Create(r.Context(), user.ID)
		if err != nil {
			h.log.Error("creating session", "err", err)
		}

		if err := h.cookie.SetUserSessionCookie(w, session.ID, &session.ExpiresAt); err != nil {
			h.log.Error("failed to set user session cookie", "err", err)
			return
		}

		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusOK)
	}
}

func (h *Handler) HandleAdminGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := h.auth.ListAllUsers(r.Context())
		if err != nil {
			h.log.Error("unable to list users", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := webmodels.BuildAdminPageCtx(users)
		h.tmpl.RenderPage(w, "admin_page", ctx, "Admin")
	}
}

func (h *Handler) HandleAdminUserRowGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := webmodels.BuildAdminPageUserTableRowCtx(user)
		h.tmpl.Render(w, "admin_page_user_table_row", ctx)
	}
}

func (h *Handler) HandleAdminUserRowEditGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := webmodels.BuildAdminPageUserTableRowEditCtx(user)
		h.tmpl.Render(w, "admin_page_user_table_row_edit", ctx)
	}
}

func (h *Handler) HandleAdminUserUpdatePut() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		var params models.UpdateUserByIDParams

		if err := r.ParseForm(); err != nil {
			h.log.Error("failed to parse form")
			http.Error(w, "failed to parse form", http.StatusBadRequest)
			return
		}
		role := models.Role(r.FormValue("role"))

		claimSlice := r.Form["claims"]
		claims := make(models.Claims)
		for _, claimStr := range claimSlice {
			parts := strings.SplitN(claimStr, ":", 2)
			resource := parts[0]
			role := models.Role("")
			if len(parts) > 1 {
				role = models.Role(parts[1])
			}
			claims[resource] = role
		}

		params.ID = usrID
		params.Role = &role
		params.Claims = &claims

		// get a copy of the user model before the update for comparison, to update state if neccessary
		var beforeUpdateUser *models.User
		beforeUpdateUser, err = h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		afterUpdateUser, err := h.auth.UpdateUserByID(r.Context(), params)
		if err != nil {
			h.log.Error("failed to update user by ID", "err", err)
			http.Error(w, "failed to update user", http.StatusInternalServerError)
			return
		}

		statsUpdateHeader := fmt.Sprintf(`{"update-stats":{"admin":%d}}`, adminCountDelta(beforeUpdateUser, afterUpdateUser))
		w.Header().Set("HX-Trigger", statsUpdateHeader)

		ctx := webmodels.BuildAdminPageUserTableRowCtx(afterUpdateUser)
		h.tmpl.Render(w, "admin_page_user_table_row", ctx)
	}
}

func (h *Handler) HandleAdminUserDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "error", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// TODO: add persistent logging for This kind of thing
		if err := h.auth.HardDeleteUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to delete user", "id", id, "err", err)
			http.Error(w, "unable to delete user", http.StatusInternalServerError)
			return
		}

		var statsUpdateHeader string
		if user.IsActive {
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"active":-1}}`
			}
		} else {
			if user.Role.AtLeast(models.RoleAdmin) {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1,"admin":-1}}`
			} else {
				statsUpdateHeader = `{"update-stats":{"total":-1,"inactive":-1}}`
			}
		}

		w.Header().Set("HX-Trigger", statsUpdateHeader)
	}
}

func (h *Handler) HandleAdminUserDisable() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := h.auth.SoftDeleteUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to disable user", "id", id, "err", err)
			http.Error(w, "unable to disable user", http.StatusInternalServerError)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("HX-Trigger", `{"update-stats":{"active":-1,"inactive":1}}`)

		ctx := webmodels.BuildAdminPageUserTableRowCtx(user)
		h.tmpl.Render(w, "admin_page_user_table_row", ctx)
	}
}

func (h *Handler) HandleAdminUserEnable() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id := r.PathValue("id")
		usrID, err := uuid.Parse(id)
		if err != nil {
			h.log.Error("unable to parse provided id into uuid", "id", id, "err", err)
			http.Error(w, "unable to parse provided id into uuid", http.StatusBadRequest)
			return
		}

		if err := h.auth.RestoreUser(r.Context(), usrID); err != nil {
			h.log.Error("unable to enable user", "id", id, "err", err)
			http.Error(w, "unable to enable user", http.StatusInternalServerError)
			return
		}

		user, err := h.auth.GetUserByID(r.Context(), usrID)
		if err != nil {
			h.log.Error("unable to list user with uuid", "uuid", usrID.String(), "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("HX-Trigger", `{"update-stats":{"active":1,"inactive":-1}}`)
		ctx := webmodels.BuildAdminPageUserTableRowCtx(user)
		h.tmpl.Render(w, "admin_page_user_table_row", ctx)
	}
}

// adminCountDelta compares the roles of beforeUpdateUser and afterUpdateUser
// and determines if the admin user count should be adjusteh.
//
// Returns:
// - +1 if the user's role was promoted from below admin to admin or higher (increment admin count)
// - -1 if the user's role was demoted from admin or higher to below admin (decrement admin count)
// - 0 if no change to admin status or if beforeUpdateUser is nil
//
// Parameters:
// - beforeUpdateUser: pointer to the User before update; may be nil if no prior data
// - afterUpdateUser: pointer to the User after update; assumed non-nil
func adminCountDelta(beforeUpdateUser, afterUpdateUser *models.User) int {
	// No change if before is nil (e.g. new user or missing claim)
	if beforeUpdateUser == nil {
		return 0
	}

	wasAdmin := beforeUpdateUser.Role.AtLeast(models.RoleAdmin)
	isAdmin := afterUpdateUser.Role.AtLeast(models.RoleAdmin)

	switch {
	case !wasAdmin && isAdmin:
		// Role went from below admin to admin or higher
		return +1
	case wasAdmin && !isAdmin:
		// Role went from admin or higher to below admin
		return -1
	default:
		return 0
	}
}

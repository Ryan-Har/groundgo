package enforcer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRoute(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMethod string
		wantPath   string
	}{
		{"MethodAndPath", "GET /admin", "GET", "/admin"},
		{"PathOnly", "/dashboard", "", "/dashboard"},
		{"EmptyString", "", "", "/"},
		{"WhitespaceOnly", "   ", "", "/"},
		{"MethodOnly", "POST", "", "/"},
		{"MethodAndPathWithSpaces", "  PUT   /api/users  ", "PUT", "/api/users"},
		{"LowercaseMethod", "get /lowercase", "GET", "/lowercase"},
		{"UppercasePath", "get /UPPERCASE", "GET", "/uppercase"},
		{"ComplexPath", "DELETE /api/v1/users/123", "DELETE", "/api/v1/users/123"},
		{"ComplexPathWithSpecialCharacters", "DELETE /api/v1.0/users/123", "DELETE", "/api/v1.0/users/123"},
		{"RootPath", "GET /", "GET", "/"},
		{"PathOnlyRoot", "/", "", "/"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotMethod, gotPath := parseRoute(tt.input)
			require.Equal(t, tt.wantMethod, gotMethod)
			require.Equal(t, tt.wantPath, gotPath)
		})
	}
}

func TestHandleRoutes(t *testing.T) {
	emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	tests := []struct {
		name        string
		route       string
		handler     http.Handler
		expectError bool
	}{
		{
			name:        "Valid GET route",
			route:       "GET /foo",
			handler:     emptyHandler,
			expectError: false,
		},
		{
			name:        "Valid wildcard route",
			route:       "/bar",
			handler:     emptyHandler,
			expectError: false,
		},
		{
			name:        "Duplicate route",
			route:       "GET /dup",
			handler:     emptyHandler,
			expectError: true,
		},
		{
			name:        "Empty route",
			route:       "",
			handler:     emptyHandler,
			expectError: false,
		},
		{
			name:        "Nil handler",
			route:       "GET /nil",
			handler:     nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enf, _ := newEnforcerFromMocks()

			// For duplicate test, register first time
			if tt.name == "Duplicate route" {
				err := enf.Handle(tt.route, tt.handler)
				require.NoError(t, err)
			}

			err := enf.Handle(tt.route, tt.handler)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Ensure handler is stored if expected
			if !tt.expectError && tt.handler != nil {
				method, path := parseRoute(tt.route)
				if path == "" {
					path = "/" // default for empty route
				}
				if _, ok := enf.handlers[path]; !ok {
					t.Fatalf("handlers[%q] not found", path)
				}
				if method != "" {
					if _, ok := enf.handlers[path][method]; !ok {
						t.Fatalf("handler for method %q not stored", method)
					}
				}
			}
		})
	}
}

func TestDispatcher(t *testing.T) {
	tests := []struct {
		name       string
		register   string
		registerFn http.HandlerFunc
		reqMethod  string
		reqPath    string
		wantCode   int
		wantBody   string
	}{
		{
			name:       "Exact method match",
			register:   "GET /hello",
			registerFn: func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("GET handler")) },
			reqMethod:  "GET",
			reqPath:    "/hello",
			wantCode:   200,
			wantBody:   "GET handler",
		},
		{
			name:     "Wildcard fallback",
			register: "/hello",
			registerFn: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				_, _ = w.Write([]byte("WILDCARD handler"))
			},
			reqMethod: "POST",
			reqPath:   "/hello",
			wantCode:  201,
			wantBody:  "WILDCARD handler",
		},
		{
			name:       "Unknown method returns 405",
			register:   "GET /onlyget",
			registerFn: func(w http.ResponseWriter, r *http.Request) {},
			reqMethod:  "POST",
			reqPath:    "/onlyget",
			wantCode:   http.StatusMethodNotAllowed,
			wantBody:   "Method Not Allowed\n",
		},
		{
			name:      "Unknown path returns 500",
			reqMethod: "GET",
			reqPath:   "/doesnotexist",
			wantCode:  http.StatusInternalServerError,
			wantBody:  "Internal Server Error\n",
		},
		{
			name:      "Nil handler returns 500",
			register:  "GET /nil",
			reqMethod: "GET",
			reqPath:   "/nil",
			wantCode:  http.StatusInternalServerError,
			wantBody:  "Internal Server Error\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enf, _ := newEnforcerFromMocks()

			// Register handler if needed
			if tt.register != "" {
				var handler http.Handler
				if tt.registerFn != nil {
					handler = tt.registerFn
				}
				_ = enf.Handle(tt.register, handler)
			}

			dispatcher := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if methods, ok := enf.handlers[r.URL.Path]; ok {
					if h, ok := methods[r.Method]; ok {
						if h == nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						h.ServeHTTP(w, r)
						return
					}
					if h, ok := methods[""]; ok {
						if h == nil {
							http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							return
						}
						h.ServeHTTP(w, r)
						return
					}
					http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
					return
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			})

			req := httptest.NewRequest(tt.reqMethod, tt.reqPath, nil)
			rec := httptest.NewRecorder()
			dispatcher.ServeHTTP(rec, req)

			require.Equal(t, tt.wantCode, rec.Code)
			require.Equal(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestDuplicatePathAndMethodError(t *testing.T) {
	err := &DuplicatePathAndMethodError{Path: "/test", Method: "GET"}
	require.EqualError(t, err, "enforcer: duplicate path: /test and method: GET attempted")
	require.True(t, errors.Is(err, &DuplicatePathAndMethodError{}))
	require.True(t, errors.Is(err, ErrDuplicatePathAndMethod))
	require.False(t, errors.Is(err, errors.New("different")))
}

func BenchmarkParseRoute(b *testing.B) {
	routes := []string{
		"GET /api/users",
		"/static",
		"POST /api/login",
		"DELETE /api/users/123",
	}
	for i := 0; i < b.N; i++ {
		parseRoute(routes[i%len(routes)])
	}
}

func BenchmarkHandle(b *testing.B) {
	handler := http.HandlerFunc(dummyHandler)
	for i := 0; i < b.N; i++ {
		e, _ := newEnforcerFromMocks()
		route := "GET /benchmark/" + strconv.Itoa(i%1000)
		_ = e.Handle(route, handler)
	}
}

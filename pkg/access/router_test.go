package access

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// mockRouter is a minimal implementation of Router for testing
// it records which patterns were handled.
type mockRouter struct {
	handledPaths []string
}

func (m *mockRouter) Handle(pattern string, handler http.Handler) {
	m.handledPaths = append(m.handledPaths, pattern)
}

// dummyHandler is a simple handler that writes a known value
func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot) // 418 I'm a teapot
	w.Write([]byte("teapot"))
}

// createTestEnforcer creates a properly initialized Enforcer for testing
func createTestEnforcer() *Enforcer {
	return &Enforcer{
		router:   &mockRouter{},
		handlers: make(map[string]map[string]http.Handler),
	}
}

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
		t.Run(tt.name, func(t *testing.T) {
			gotMethod, gotPath := parseRoute(tt.input)
			if gotMethod != tt.wantMethod || gotPath != tt.wantPath {
				t.Errorf("parseRoute(%q) = (%q, %q), want (%q, %q)",
					tt.input, gotMethod, gotPath, tt.wantMethod, tt.wantPath)
			}
		})
	}
}

func TestHandle_Success(t *testing.T) {
	e := createTestEnforcer()

	err := e.Handle("GET /foo", http.HandlerFunc(dummyHandler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify handler is stored
	h, ok := e.handlers["/foo"]["GET"]
	if !ok {
		t.Fatal("expected handler for GET /foo not found")
	}
	if h == nil {
		t.Error("handler is nil")
	}

	// Verify router.Handle was called exactly once
	mRouter := e.router.(*mockRouter)
	if len(mRouter.handledPaths) != 1 {
		t.Fatalf("router.Handle should have been called once, got %d", len(mRouter.handledPaths))
	}
	if mRouter.handledPaths[0] != "/foo" {
		t.Errorf("router.Handle called with %q, want %q", mRouter.handledPaths[0], "/foo")
	}
}

func TestHandle_InitializesHandlersMap(t *testing.T) {
	e := &Enforcer{
		router: &mockRouter{},
		// handlers is nil initially
	}

	err := e.Handle("GET /test", http.HandlerFunc(dummyHandler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if e.handlers == nil {
		t.Fatal("handlers map should be initialized")
	}

	if _, ok := e.handlers["/test"]["GET"]; !ok {
		t.Error("handler should be stored after initialization")
	}
}

func TestHandle_DuplicateRoute(t *testing.T) {
	e := createTestEnforcer()

	// First registration
	err := e.Handle("GET /dup", http.HandlerFunc(dummyHandler))
	if err != nil {
		t.Fatalf("unexpected error on first handle: %v", err)
	}

	// Duplicate registration
	err = e.Handle("GET /dup", http.HandlerFunc(dummyHandler))
	if err == nil {
		t.Fatal("expected error for duplicate route, got nil")
	}

	var dupErr *DuplicatePathAndMethodError
	if !errors.As(err, &dupErr) {
		t.Errorf("expected DuplicatePathAndMethodError, got %T", err)
	}

	if dupErr.Path != "/dup" || dupErr.Method != "GET" {
		t.Errorf("error details: got Path=%q Method=%q, want Path=%q Method=%q",
			dupErr.Path, dupErr.Method, "/dup", "GET")
	}

	if got := err.Error(); !strings.Contains(got, "/dup") || !strings.Contains(got, "GET") {
		t.Errorf("error message missing details: %q", got)
	}
}

func TestHandle_WildcardRoute(t *testing.T) {
	e := createTestEnforcer()

	err := e.Handle("/bar", http.HandlerFunc(dummyHandler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := e.handlers["/bar"][""]; !ok {
		t.Fatal("expected wildcard handler stored for /bar")
	}
}

func TestHandle_MultipleMethodsSamePath(t *testing.T) {
	e := createTestEnforcer()

	methods := []string{"GET", "POST", "PUT", "DELETE"}
	for _, method := range methods {
		err := e.Handle(method+" /api", http.HandlerFunc(dummyHandler))
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", method, err)
		}
	}

	for _, method := range methods {
		if _, ok := e.handlers["/api"][method]; !ok {
			t.Errorf("handler for %s /api not found", method)
		}
	}

	mRouter := e.router.(*mockRouter)
	if len(mRouter.handledPaths) != 1 {
		t.Errorf("router.Handle should be called once per path, got %d calls", len(mRouter.handledPaths))
	}
}

func TestHandleFunc_DelegatesToHandle(t *testing.T) {
	e := createTestEnforcer()

	err := e.HandleFunc("GET /baz", dummyHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := e.handlers["/baz"]["GET"]; !ok {
		t.Fatal("expected handler for GET /baz not stored")
	}
}

// Single dispatcher test with subtests
func TestDispatcher(t *testing.T) {
	makeDispatcher := func(e *Enforcer) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if methods, ok := e.handlers[r.URL.Path]; ok {
				if h, ok := methods[r.Method]; ok {
					if h == nil {
						http.Error(w, "nil handler", http.StatusInternalServerError)
						return
					}
					h.ServeHTTP(w, r)
					return
				}
				if h, ok := methods[""]; ok {
					if h == nil {
						http.Error(w, "nil handler", http.StatusInternalServerError)
						return
					}
					h.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			// path not found
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		})
	}

	t.Run("ExactMethodMatch", func(t *testing.T) {
		e := createTestEnforcer()
		e.Handle("GET /hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("GET handler"))
		}))
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("GET", "/hello", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)

		if rec.Code != 200 {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
		if body := rec.Body.String(); body != "GET handler" {
			t.Errorf("expected body 'GET handler', got %q", body)
		}
	})

	t.Run("WildcardFallback", func(t *testing.T) {
		e := createTestEnforcer()
		e.Handle("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			w.Write([]byte("WILDCARD handler"))
		}))
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("POST", "/hello", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)

		if rec.Code != 201 {
			t.Errorf("expected status 201, got %d", rec.Code)
		}
		if body := rec.Body.String(); body != "WILDCARD handler" {
			t.Errorf("expected body 'WILDCARD handler', got %q", body)
		}
	})

	t.Run("MethodPriority", func(t *testing.T) {
		e := createTestEnforcer()
		e.Handle("GET /hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("specific"))
		}))
		e.Handle("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("wildcard"))
		}))
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("GET", "/hello", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)
		if body := rec.Body.String(); body != "specific" {
			t.Errorf("expected 'specific', got %q", body)
		}

		req = httptest.NewRequest("POST", "/hello", nil)
		rec = httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)
		if body := rec.Body.String(); body != "wildcard" {
			t.Errorf("expected 'wildcard', got %q", body)
		}
	})

	t.Run("UnknownMethodReturns405", func(t *testing.T) {
		e := createTestEnforcer()
		e.Handle("GET /onlyget", http.HandlerFunc(dummyHandler))
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("POST", "/onlyget", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rec.Code)
		}
	})

	t.Run("UnknownPathReturns500", func(t *testing.T) {
		e := createTestEnforcer()
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("GET", "/doesnotexist", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("NilHandlerReturns500", func(t *testing.T) {
		e := createTestEnforcer()
		e.Handle("GET /nil", nil)
		dispatcher := makeDispatcher(e)

		req := httptest.NewRequest("GET", "/nil", nil)
		rec := httptest.NewRecorder()
		dispatcher.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}
	})
}

func TestDuplicatePathAndMethodError_Error(t *testing.T) {
	err := &DuplicatePathAndMethodError{
		Path:   "/test",
		Method: "GET",
	}

	expected := "enforcer: duplicate path: /test and method: GET attempted"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestDuplicatePathAndMethodError_Is(t *testing.T) {
	err1 := &DuplicatePathAndMethodError{Path: "/test", Method: "GET"}
	err2 := &DuplicatePathAndMethodError{Path: "/other", Method: "POST"}

	if !errors.Is(err1, err2) {
		t.Error("DuplicatePathAndMethodError should match other instances")
	}

	if errors.Is(err1, errors.New("different error")) {
		t.Error("DuplicatePathAndMethodError should not match different error types")
	}
}

func TestErrDuplicatePathAndMethod_Sentinel(t *testing.T) {
	err := &DuplicatePathAndMethodError{Path: "/test", Method: "GET"}

	if !errors.Is(err, ErrDuplicatePathAndMethod) {
		t.Error("should match sentinel error")
	}
}

// --- edge cases ---

func TestHandle_EmptyRoute(t *testing.T) {
	e := createTestEnforcer()

	err := e.Handle("", http.HandlerFunc(dummyHandler))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := e.handlers["/"][""]; !ok {
		t.Error("empty route should default to wildcard root")
	}
}

func TestHandle_NilHandler(t *testing.T) {
	e := createTestEnforcer()

	err := e.Handle("GET /nil", nil)
	if err == nil {
		t.Fatal("expected error for nil handler, got none")
	}
}

// --- benchmark tests ---

func BenchmarkParseRoute(b *testing.B) {
	routes := []string{
		"GET /api/users",
		"/static",
		"POST /api/login",
		"DELETE /api/users/123",
	}

	for i := 0; i < b.N; i++ {
		route := routes[i%len(routes)]
		parseRoute(route)
	}
}

func BenchmarkHandle(b *testing.B) {
	handler := http.HandlerFunc(dummyHandler)
	for i := 0; i < b.N; i++ {
		e := createTestEnforcer()
		route := "GET /benchmark/" + strconv.Itoa(i%1000)
		e.Handle(route, handler)
	}
}

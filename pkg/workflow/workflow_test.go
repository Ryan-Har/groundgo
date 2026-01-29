package workflow

import (
	"github.com/Ryan-Har/groundgo/internal/testutil"
	"github.com/Ryan-Har/groundgo/pkg/apidetector"
	"github.com/Ryan-Har/groundgo/pkg/store"
)

// newWorkflowFromMocks is a helper which provides a workflow type with mocks
func newWorkflowFromMocks() (*Workflow, *testutil.AuthStoreMock, *testutil.SessionStoreMock, *testutil.TokenStoreMock, *testutil.CookieStoreMock) {
	// Create mocks for all stores
	auth := &testutil.AuthStoreMock{}
	session := &testutil.SessionStoreMock{}
	token := &testutil.TokenStoreMock{}
	cookie := &testutil.CookieStoreMock{}

	// Create a test store that bundles all mocks
	store := store.Store{
		Auth:    auth,
		Session: session,
		Token:   token,
		Cookie:  cookie,
	}

	// Create the Workflow instance
	wf := &Workflow{
		store:       store,
		log:         testutil.NoopLogger(),
		apiDetector: apidetector.Default,
	}

	return wf, auth, session, token, cookie
}

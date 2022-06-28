package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAuth_authCmd(t *testing.T) {
	testutil.UnitTest(t)
	ctx := context.Background()
	authenticator := New(error_reporting.NewTestErrorReporter())

	authCmd, err := authenticator.authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

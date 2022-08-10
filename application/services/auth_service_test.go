package services

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_UpdateToken(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	service := NewAuthenticationService(&auth.CliAuthenticationProvider{}, analytics)

	service.UpdateToken("new-token")

	assert.Equal(t, "new-token", config.CurrentConfig().Token())
	assert.True(t, analytics.Identified)
}

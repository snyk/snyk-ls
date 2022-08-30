package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_UpdateToken(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	service := NewAuthenticationService(&auth.CliAuthenticationProvider{}, analytics, error_reporting.NewTestErrorReporter())

	service.UpdateToken("new-token", false)

	assert.Equal(t, "new-token", config.CurrentConfig().Token())
	assert.True(t, analytics.Identified)
}

func Test_Logout(t *testing.T) {
	testutil.IntegTest(t)

	// arrange
	// set up workspace
	analytics := ux.NewTestAnalytics()
	authProvider := auth.FakeAuthenticationProvider{}
	service := NewAuthenticationService(&authProvider, analytics, error_reporting.NewTestErrorReporter())
	hoverService := hover.NewFakeHoverService()
	scanner := snyk.NewTestScanner()
	w := workspace.New(performance.NewTestInstrumentor(), scanner, hoverService)
	workspace.Set(w)
	f := workspace.NewFolder("", "", scanner, hoverService)
	w.AddFolder(f)

	// fake existing diagnostic & hover
	issueFile := "path/to/file.test"
	issue := snyk.Issue{AffectedFilePath: issueFile}
	scanner.AddTestIssue(issue)
	f.ScanFile(context.Background(), issueFile)

	testIssue := snyk.Issue{FormattedMessage: "<br><br/><br />"}
	hovers := converter.ToHovers([]snyk.Issue{testIssue})

	_, _ = service.authenticator.Authenticate(context.Background())

	hoverService.Channel() <- hover.DocumentHovers{
		Uri:   "path/to/file.test",
		Hover: hovers,
	}

	// act
	service.Logout(context.Background())

	// assert
	assert.False(t, authProvider.IsAuthenticated)
	assert.Len(t, 0, len(hoverService.Channel()))
	assert.Len(t, f.AllIssuesFor(issueFile), 0)
}

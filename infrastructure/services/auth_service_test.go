/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_UpdateToken(t *testing.T) {
	testutil.UnitTest(t)
	analytics := ux.NewTestAnalytics()
	service := NewAuthenticationService(&snyk_api.FakeApiClient{}, &auth.CliAuthenticationProvider{}, analytics, error_reporting.NewTestErrorReporter())

	service.UpdateToken("new-token", false)

	assert.Equal(t, "new-token", config.CurrentConfig().Token())
	assert.True(t, analytics.Identified)
}

func Test_IsAuthenticated(t *testing.T) {
	t.Run("User is authenticated", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()

		service := NewAuthenticationService(
			&snyk_api.FakeApiClient{},
			&auth.CliAuthenticationProvider{},
			analytics,
			error_reporting.NewTestErrorReporter(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.True(t, isAuthenticated)
		assert.NoError(t, err)
	})

	t.Run("User is not authenticated", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()
		snykApiError := snyk_api.NewSnykApiError("error", 401)

		service := NewAuthenticationService(
			&snyk_api.FakeApiClient{ApiError: snykApiError},
			&auth.FakeAuthenticationProvider{},
			analytics,
			error_reporting.NewTestErrorReporter(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
		assert.Equal(t, err.Error(), "Authentication failed. Please update your token.")
	})

	t.Run("Other authentication error", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()
		snykApiError := snyk_api.NewSnykApiError("error", 503)

		service := NewAuthenticationService(
			&snyk_api.FakeApiClient{ApiError: snykApiError},
			&auth.FakeAuthenticationProvider{},
			analytics,
			error_reporting.NewTestErrorReporter(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
		assert.Equal(t, err.Error(), snykApiError.Error())
	})
}

func Test_Logout(t *testing.T) {
	testutil.IntegTest(t)

	// arrange
	// set up workspace
	analytics := ux.NewTestAnalytics()
	authProvider := auth.FakeAuthenticationProvider{}
	service := NewAuthenticationService(&snyk_api.FakeApiClient{}, &authProvider, analytics, error_reporting.NewTestErrorReporter())
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
	assert.Equal(t, 0, len(hoverService.Channel()))
	assert.Len(t, f.AllIssuesFor(issueFile), 0)
}

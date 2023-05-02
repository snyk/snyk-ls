/*
 * © 2022-2023 Snyk Limited
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

package snyk_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_UpdateCredentials(t *testing.T) {
	t.Run("CLI Authentication", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()
		service := snyk.NewAuthenticationService(
			nil,
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		service.UpdateCredentials("new-token", false)

		assert.Equal(t, "new-token", config.CurrentConfig().Token())
	})

	t.Run("OAuth Authentication Authentication", func(t *testing.T) {
		testutil.UnitTest(t)
		config.CurrentConfig().SetAuthenticationMethod(lsp.OAuthAuthentication)
		analytics := ux.NewTestAnalytics()
		service := snyk.NewAuthenticationService(nil, analytics, error_reporting.NewTestErrorReporter(), notification.NewNotifier())
		oauthCred := oauth2.Token{
			AccessToken:  t.Name(),
			TokenType:    "b",
			RefreshToken: "c",
			Expiry:       time.Time{},
		}
		tokenBytes, err := json.Marshal(oauthCred)
		assert.NoError(t, err)
		token := string(tokenBytes)

		service.UpdateCredentials(token, false)

		assert.Equal(t, token, config.CurrentConfig().Token())
	})
}

func Test_IsAuthenticated(t *testing.T) {
	t.Run("User is authenticated", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()

		service := snyk.NewAuthenticationService(
			&snyk.FakeAuthenticationProvider{IsAuthenticated: true},
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.True(t, isAuthenticated)
		assert.NoError(t, err)
	})

	t.Run("User is not authenticated", func(t *testing.T) {
		testutil.UnitTest(t)
		analytics := ux.NewTestAnalytics()
		service := snyk.NewAuthenticationService(
			&snyk.FakeAuthenticationProvider{IsAuthenticated: false},
			analytics,
			error_reporting.NewTestErrorReporter(),
			notification.NewNotifier(),
		)

		isAuthenticated, err := service.IsAuthenticated()

		assert.False(t, isAuthenticated)
		assert.Equal(t, err.Error(), "Authentication failed. Please update your token.")
	})
}

func Test_Logout(t *testing.T) {
	testutil.IntegTest(t)

	// arrange
	// set up workspace
	notifier := notification.NewNotifier()
	analytics := ux.NewTestAnalytics()
	authProvider := snyk.FakeAuthenticationProvider{}
	service := snyk.NewAuthenticationService(&authProvider, analytics, error_reporting.NewTestErrorReporter(), notifier)
	hoverService := hover.NewFakeHoverService()
	scanner := snyk.NewTestScanner()
	scanNotifier, _ := appNotification.NewScanNotifier(notifier)
	w := workspace.New(performance.NewTestInstrumentor(), scanner, hoverService, scanNotifier, notifier)
	workspace.Set(w)
	f := workspace.NewFolder("", "", scanner, hoverService, scanNotifier, notifier)
	w.AddFolder(f)

	// fake existing diagnostic & hover
	issueFile := "path/to/file.test"
	issue := snyk.Issue{AffectedFilePath: issueFile}
	scanner.AddTestIssue(issue)
	f.ScanFile(context.Background(), issueFile)

	testIssue := snyk.Issue{FormattedMessage: "<br><br/><br />"}
	hovers := converter.ToHovers([]snyk.Issue{testIssue})

	_, _ = service.Provider().Authenticate(context.Background())

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

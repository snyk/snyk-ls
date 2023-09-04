/*
 * © 2023 Snyk Limited
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

package command

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestLogoutCommand_Execute_ClearsIssues(t *testing.T) {
	testutil.UnitTest(t)
	notifier := notification.NewNotifier()
	provider := snyk.NewFakeCliAuthenticationProvider()
	hoverService := hover.NewFakeHoverService()
	provider.IsAuthenticated = true
	scanNotifier := snyk.NewMockScanNotifier()
	authenticationService := snyk.NewAuthenticationService(
		provider,
		ux.NewTestAnalytics(),
		error_reporting.NewTestErrorReporter(),
		notifier,
	)
	cmd := logoutCommand{
		command:     snyk.CommandData{CommandId: snyk.LogoutCommand},
		authService: authenticationService,
	}

	scanner := snyk.NewTestScanner()
	scanner.Issues = []snyk.Issue{{ID: "issue-1"}}

	w := workspace.New(performance.NewInstrumentor(), scanner, hoverService, scanNotifier, notifier)
	folder := workspace.NewFolder(
		t.TempDir(),
		t.Name(),
		scanner,
		hoverService,
		scanNotifier,
		notifier,
	)
	workspace.Set(w)
	w.AddFolder(folder)

	ctx := context.Background()

	folder.ScanFolder(ctx)

	_, err := cmd.Execute(ctx)

	assert.NoError(t, err)
	authenticated, err := authenticationService.IsAuthenticated()
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, folder.AllIssuesFor(t.TempDir()))
	assert.Empty(t, len(hoverService.Channel()))
}

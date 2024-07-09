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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/observability/ux"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestLogoutCommand_Execute_ClearsIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewNotifier()
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	hoverService := hover.NewFakeHoverService()
	provider.IsAuthenticated = true
	scanNotifier := snyk.NewMockScanNotifier()
	authenticationService := authentication.NewAuthenticationService(
		c,
		[]authentication.AuthenticationProvider{provider},
		ux.NewTestAnalytics(c),
		error_reporting.NewTestErrorReporter(),
		notifier,
	)
	cmd := logoutCommand{
		command:     types.CommandData{CommandId: types.LogoutCommand},
		authService: authenticationService,
		logger:      c.Logger(),
	}

	scanner := snyk.NewTestScanner()

	w := workspace.New(c, performance.NewInstrumentor(), scanner, hoverService, scanNotifier, notifier)
	folder := workspace.NewFolder(
		c,
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
	path := filepath.Join(folder.Path(), "path1")
	scanner.AddTestIssue(snyk.Issue{ID: "issue-1", AffectedFilePath: path})

	folder.ScanFolder(ctx)

	_, err := cmd.Execute(ctx)

	assert.NoError(t, err)
	authenticated, err := authenticationService.IsAuthenticated()
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, folder.IssuesForFile(t.TempDir()))
	assert.Empty(t, len(hoverService.Channel()))
}

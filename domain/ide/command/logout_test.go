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

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestLogoutCommand_Execute_ClearsIssues(t *testing.T) {
	c := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	provider := authentication.NewFakeCliAuthenticationProvider(c)
	hoverService := hover.NewFakeHoverService()
	provider.IsAuthenticated = true
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	authenticationService := authentication.NewAuthenticationService(c, provider, error_reporting.NewTestErrorReporter(), notifier)
	cmd := logoutCommand{
		command:     types.CommandData{CommandId: types.LogoutCommand},
		authService: authenticationService,
		c:           c,
	}

	sc := scanner.NewTestScanner()

	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	folder := workspace.NewFolder(
		c,
		types.FilePath(t.TempDir()),
		t.Name(),
		sc,
		hoverService,
		scanNotifier,
		notifier,
		scanPersister,
		scanStateAggregator,
	)
	c.SetWorkspace(w)
	w.AddFolder(folder)

	ctx := context.Background()
	path := types.FilePath(filepath.Join(string(folder.Path()), "path1"))
	sc.AddTestIssue(snyk.Issue{ID: "issue-1", AffectedFilePath: path})

	folder.ScanFolder(ctx)

	_, err := cmd.Execute(ctx)

	assert.NoError(t, err)
	authenticated := authenticationService.IsAuthenticated()
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, folder.IssuesForFile(types.FilePath(t.TempDir())))
	assert.Empty(t, len(hoverService.Channel()))
}

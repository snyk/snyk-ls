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
	"path/filepath"
	"testing"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestLogoutCommand_Execute_ClearsIssues(t *testing.T) {
	engine, tokenService := testutil.UnitTestWithEngine(t)
	notifier := notification.NewMockNotifier()
	provider := authentication.NewFakeCliAuthenticationProvider(engine)
	hoverService := hover.NewFakeHoverService()
	provider.IsAuthenticated = true
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	fakeFeatureFlagService := featureflag.NewFakeService()
	authenticationService := authentication.NewAuthenticationService(engine, tokenService, provider, error_reporting.NewTestErrorReporter(engine), notifier)
	cmd := logoutCommand{
		command:            types.CommandData{CommandId: types.LogoutCommand},
		authService:        authenticationService,
		featureFlagService: fakeFeatureFlagService,
		engine:             engine,
	}

	sc := scanner.NewTestScanner()

	resolver := types.NewConfigResolver(engine.GetLogger())
	w := workspace.New(engine.GetConfiguration(), engine.GetLogger(), performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, fakeFeatureFlagService, resolver, engine)
	folder := workspace.NewFolder(
		engine.GetConfiguration(),
		engine.GetLogger(),
		types.FilePath(t.TempDir()),
		t.Name(),
		sc,
		hoverService,
		scanNotifier,
		notifier,
		scanPersister,
		scanStateAggregator,
		fakeFeatureFlagService,
		resolver,
		engine,
	)
	config.SetWorkspace(engine.GetConfiguration(), w)
	w.AddFolder(folder)

	ctx := t.Context()
	path := types.FilePath(filepath.Join(string(folder.Path()), "path1"))
	sc.AddTestIssue(&snyk.Issue{ID: "issue-1", AffectedFilePath: path})

	folder.ScanFolder(ctx)

	_, err := cmd.Execute(ctx)

	assert.NoError(t, err)
	authenticated := authenticationService.IsAuthenticated()
	assert.NoError(t, err)
	assert.False(t, authenticated)
	assert.Empty(t, folder.IssuesForFile(types.FilePath(t.TempDir())))
	assert.Empty(t, len(hoverService.Channel()))
}

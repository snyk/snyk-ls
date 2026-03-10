/*
 * © 2024 Snyk Limited
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
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ClearCache_DeleteAll_NoError(t *testing.T) {
	engine := testutil.UnitTest(t)

	// Arrange
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewGitPersistenceProvider(engine.GetLogger(), engine.GetConfiguration())
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := types.NewConfigResolver(engine.GetLogger())
	w := workspace.New(engine.GetConfiguration(), engine.GetLogger(), performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	folder := workspace.NewFolder(engine.GetConfiguration(), engine.GetLogger(), types.PathKey("dummy"), "dummy", sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
	w.AddFolder(folder)
	config.SetWorkspace(engine.GetConfiguration(), w)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingScanAutomatic), false)

	clearCacheCommand := setupClearCacheCommand(t, "", "", engine)

	// Execute the command
	_, err := clearCacheCommand.Execute(t.Context())

	// Assert
	assert.NoError(t, err)
}

func setupClearCacheCommand(t *testing.T, folderUri, cacheType string, engine workflow.Engine) clearCache {
	t.Helper()
	clearCacheCmd := clearCache{
		command: types.CommandData{Arguments: []interface{}{folderUri, cacheType}},
		engine:  engine,
	}
	return clearCacheCmd
}

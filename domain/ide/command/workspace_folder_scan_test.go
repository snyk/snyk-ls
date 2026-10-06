/*
 * © 2026 Snyk Limited
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

	"github.com/stretchr/testify/require"

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

func Test_WorkspaceFolderScanCommand_NestedFolder_ScansOnlyThatFolder(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	notifier := notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	resolver := testutil.DefaultConfigResolver(engine)

	parentPath := types.FilePath(filepath.Join(t.TempDir(), "repo"))
	nestedPath := types.FilePath(filepath.Join(string(parentPath), "src"))

	for i := 0; i < testutil.NestedFolderLookupRepetitions; i++ {
		parentScanner := scanner.NewTestScanner()
		nestedScanner := scanner.NewTestScanner()

		w := workspace.New(conf, logger, performance.NewInstrumentor(), parentScanner, nil, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine)
		w.AddFolder(workspace.NewFolder(conf, logger, parentPath, "repo", parentScanner, nil, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine))
		w.AddFolder(workspace.NewFolder(conf, logger, nestedPath, "src", nestedScanner, nil, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService(), resolver, engine))
		config.SetWorkspace(conf, w)

		cmd := workspaceFolderScanCommand{
			command: types.CommandData{CommandId: types.WorkspaceFolderScanCommand, Arguments: []any{string(nestedPath)}},
			engine:  engine,
		}
		_, err := cmd.Execute(t.Context())

		require.NoError(t, err)
		require.Equal(t, 1, nestedScanner.Calls(), "the requested nested folder must be scanned")
		require.Equal(t, 0, parentScanner.Calls(), "the parent folder must not be scanned in place of the nested one")
	}
}

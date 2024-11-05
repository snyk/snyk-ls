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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ClearCache_DeleteAll_NoError(t *testing.T) {
	c := testutil.UnitTest(t)

	// Arrange
	sc := &scanner.TestScanner{}
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewGitPersistenceProvider(c.Logger())
	w := workspace.New(c, performance.NewInstrumentor(), sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister)
	folder := workspace.NewFolder(c, "dummy", "dummy", sc, nil, scanNotifier, notification.NewMockNotifier(), scanPersister)
	w.AddFolder(folder)
	c.SetWorkspace(w)

	clearCacheCommand := setupClearCacheCommand(t, "", "", c)

	// Execute the command
	_, err := clearCacheCommand.Execute(context.Background())

	// Assert
	assert.NoError(t, err)
}

func setupClearCacheCommand(t *testing.T, folderUri, cacheType string, c *config.Config) clearCache {
	t.Helper()
	clearCacheCmd := clearCache{
		command: types.CommandData{Arguments: []interface{}{folderUri, cacheType}},
		c:       c,
	}
	return clearCacheCmd
}

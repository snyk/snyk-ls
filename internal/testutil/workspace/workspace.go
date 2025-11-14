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

// Package workspace provides workspace setup utilities for tests.
// This is in a separate package to avoid import cycles (testutil -> scanner -> authentication -> cli).
package workspace

import (
	"strconv"
	"testing"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/types"
)

// SetupWorkspace creates a minimal workspace if it doesn't exist and adds the given folder paths to it.
// This is useful for tests that need a workspace but don't need organization configuration.
// Returns the workspace that was created or already existed.
func SetupWorkspace(t *testing.T, c *config.Config, folderPaths ...types.FilePath) types.Workspace {
	t.Helper()

	// Create a minimal workspace if it doesn't exist
	if c.Workspace() == nil {
		w := workspace.New(
			c,
			performance.NewInstrumentor(),
			&scanner.TestScanner{},
			nil,
			scanner.NewMockScanNotifier(),
			notification.NewMockNotifier(),
			persistence.NewNopScanPersister(),
			scanstates.NewNoopStateAggregator(),
			featureflag.NewFakeService(),
		)
		c.SetWorkspace(w)
	}

	// Add folders to workspace
	for i, folderPath := range folderPaths {
		folderName := "test-folder"
		if len(folderPaths) > 1 {
			folderName = "test-folder-" + strconv.Itoa(i)
		}
		folder := workspace.NewFolder(
			c,
			folderPath,
			folderName,
			&scanner.TestScanner{},
			nil,
			scanner.NewMockScanNotifier(),
			notification.NewMockNotifier(),
			persistence.NewNopScanPersister(),
			scanstates.NewNoopStateAggregator(),
			featureflag.NewFakeService(),
		)
		c.Workspace().AddFolder(folder)
	}

	return c.Workspace()
}

/*
 * © 2025 Snyk Limited All rights reserved.
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

// Package testutils provides test utilities for command package tests.
package testutils

import (
	"strconv"
	"testing"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
)

// SetupFakeWorkspace creates a fake test workspace with the specified number of folders.
// Uses mock/fake implementations - designed for unit tests, NOT for smoke tests.
// Returns the mock notifier and the folder paths created.
func SetupFakeWorkspace(t *testing.T, c *config.Config, folderCount int) (
	notifier *notification.MockNotifier,
	folderPaths []types.FilePath,
) {
	t.Helper()

	// Create mock dependencies
	instrumentor := performance.NewInstrumentor()
	notifier = notification.NewMockNotifier()
	scanNotifier := scanner.NewMockScanNotifier()
	scanPersister := persistence.NewNopScanPersister()
	scanStateAggregator := scanstates.NewNoopStateAggregator()
	sc := scanner.NewTestScanner()
	hoverService := hover.NewFakeHoverService()
	ffService := featureflag.NewFakeService()

	// Create workspace
	w := workspace.New(c, instrumentor, sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, ffService)

	// Create and add folders with fake paths
	safeTestName := testsupport.PathSafeTestName(t)
	folderPaths = make([]types.FilePath, folderCount)
	for i := range folderCount {
		folderPath := types.FilePath("/fake/test-folder-" + strconv.Itoa(i))
		folderPaths[i] = folderPath
		folderName := safeTestName + "_test-folder_" + strconv.Itoa(i)
		folder := workspace.NewFolder(c, folderPath, folderName, sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureflag.NewFakeService())
		w.AddFolder(folder)
	}

	// Set workspace on config
	c.SetWorkspace(w)

	return notifier, folderPaths
}

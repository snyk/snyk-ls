/*
 * © 2025 Snyk Limited
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

// Package workspaceutil provides workspace setup utilities for tests.
// This is in a separate package to avoid import cycles (testutil -> scanner -> authentication -> cli).
package workspaceutil

import (
	"strconv"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

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
func SetupWorkspace(t *testing.T, engine workflow.Engine, folderPaths ...types.FilePath) (types.Workspace, *notification.MockNotifier) {
	t.Helper()
	return SetupWorkspaceWithFeatureFlags(t, engine, nil, folderPaths...)
}

// SetupWorkspaceWithFeatureFlags is like SetupWorkspace but uses the provided FakeFeatureFlagService
// for each folder. Pass nil to use a default empty fake service. Use this when the test needs to
// control feature flags (e.g. SnykCodeConsistentIgnores) that affect folder-level behavior.
func SetupWorkspaceWithFeatureFlags(t *testing.T, engine workflow.Engine, ffSvc *featureflag.FakeFeatureFlagService, folderPaths ...types.FilePath) (types.Workspace, *notification.MockNotifier) {
	t.Helper()

	if ffSvc == nil {
		ffSvc = featureflag.NewFakeService()
	}

	notifier := notification.NewMockNotifier()

	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()
	fs := pflag.NewFlagSet("workspaceutil", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	resolver := types.NewConfigResolver(logger)
	resolver.SetPrefixKeyResolver(configresolver.New(gafConf, fm), gafConf, fm)

	if config.GetWorkspace(gafConf) == nil {
		w := workspace.New(
			gafConf,
			logger,
			performance.NewInstrumentor(),
			&scanner.TestScanner{},
			nil,
			scanner.NewMockScanNotifier(),
			notifier,
			persistence.NewNopScanPersister(),
			scanstates.NewNoopStateAggregator(),
			ffSvc,
			resolver,
			engine,
		)
		config.SetWorkspace(gafConf, w)
	}

	for i, folderPath := range folderPaths {
		folderName := "test-folder"
		if len(folderPaths) > 1 {
			folderName = "test-folder-" + strconv.Itoa(i)
		}
		clean := types.PathKey(folderPath)
		folder := workspace.NewFolder(
			gafConf,
			logger,
			clean,
			folderName,
			&scanner.TestScanner{},
			nil,
			scanner.NewMockScanNotifier(),
			notifier,
			persistence.NewNopScanPersister(),
			scanstates.NewNoopStateAggregator(),
			ffSvc,
			resolver,
			engine,
		)
		config.GetWorkspace(gafConf).AddFolder(folder)

		// Populate feature flags into config so FolderConfigReadOnly() picks them up.
		// This mirrors the production path: processFolderConfigs calls ffSvc.PopulateFolderConfig.
		if folderCfg := folder.FolderConfigReadOnly(); folderCfg != nil {
			ffSvc.PopulateFolderConfig(folderCfg)
		}
	}

	return config.GetWorkspace(gafConf), notifier
}

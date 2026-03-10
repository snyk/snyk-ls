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

	notifier := notification.NewMockNotifier()

	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()
	fs := pflag.NewFlagSet("workspaceutil", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConf.AddFlagSet(fs)
	fm := workflow.NewFlagMetadata(workflow.ConfigurationOptionsFromFlagset(fs))
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
			featureflag.NewFakeService(),
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
			featureflag.NewFakeService(),
			resolver,
			engine,
		)
		config.GetWorkspace(gafConf).AddFolder(folder)
	}

	return config.GetWorkspace(gafConf), notifier
}

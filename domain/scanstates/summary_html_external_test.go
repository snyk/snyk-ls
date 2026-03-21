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

package scanstates_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_Summary_Html_DeduplicatesIssuesByFingerprint(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	folderPath := types.FilePath(t.TempDir())
	notifier := notification.NewMockNotifier()
	resolver := types.NewConfigResolver(logger)

	w := workspace.New(
		conf,
		logger,
		performance.NewInstrumentor(),
		scanner.NewTestScanner(),
		hover.NewFakeHoverService(),
		scanner.NewMockScanNotifier(),
		notifier,
		persistence.NewNopScanPersister(),
		scanstates.NewNoopStateAggregator(),
		featureflag.NewFakeService(),
		resolver,
		engine,
	)
	config.SetWorkspace(conf, w)

	folder := workspace.NewFolder(
		conf,
		logger,
		folderPath,
		"test-folder",
		scanner.NewTestScanner(),
		hover.NewFakeHoverService(),
		scanner.NewMockScanNotifier(),
		notifier,
		persistence.NewNopScanPersister(),
		scanstates.NewNoopStateAggregator(),
		featureflag.NewFakeService(),
		resolver,
		engine,
	)
	w.AddFolder(folder)

	file1 := types.FilePath(filepath.Join(string(folderPath), "secrets.yaml"))
	sharedFingerprint := "shared-fp-abc"

	issue1 := testutil.NewMockIssue("loc-1", file1)
	issue1.Fingerprint = sharedFingerprint
	issue1.Product = product.ProductSecrets

	issue2 := testutil.NewMockIssue("loc-2", file1)
	issue2.Fingerprint = sharedFingerprint
	issue2.Product = product.ProductSecrets

	issue3 := testutil.NewMockIssue("loc-3", file1)
	issue3.Fingerprint = sharedFingerprint
	issue3.Product = product.ProductSecrets

	issue4 := testutil.NewMockIssue("different-issue", file1)
	issue4.Product = product.ProductSecrets

	scanData := types.ScanData{
		Product:           product.ProductSecrets,
		Issues:            []types.Issue{issue1, issue2, issue3, issue4},
		UpdateGlobalCache: true,
	}
	folder.ScanResultProcessor()(context.Background(), scanData)

	renderer, err := scanstates.NewHtmlRenderer(conf, logger, engine, resolver)
	require.NoError(t, err)

	html := renderer.GetSummaryHtml(scanstates.StateSnapshot{
		AnyScanSucceededWorkingDirectory: true,
	})

	// 3 issues share fingerprint → count as 1, plus 1 distinct issue = 2 total
	assert.Contains(t, html, ">2 total<", "total toggle should show deduplicated count")
	assert.Contains(t, html, `<span class="snx-highlight">2 issues</span> found`, "summary body should show deduplicated count")
}

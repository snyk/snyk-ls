/*
 * © 2026 Snyk Limited All rights reserved.
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

package workspace

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ProcessResults_whenIssueHasEmptyFilePath_skipsIssue(t *testing.T) {
	engine := testutil.UnitTest(t)
	notifier := notification.NewMockNotifier()
	f := NewMockFolder(engine, notifier)
	setupWorkspaceWithFolder(engine, f, notifier)

	validPath := types.FilePath(filepath.Join(string(f.path), "build.gradle.kts"))
	data := types.ScanData{
		Product: product.ProductOpenSource,
		Issues: []types.Issue{
			testutil.NewMockIssue("trove4j-with-path", validPath),
			testutil.NewMockIssue("trove4j-no-path", ""),
		},
		UpdateGlobalCache: true,
		SendAnalytics:     true,
	}

	assert.NotPanics(t, func() {
		f.ProcessResults(t.Context(), data)
	})
	assert.Len(t, f.IssuesForFile(validPath), 1)
	assert.Empty(t, f.IssuesForFile(""))
}

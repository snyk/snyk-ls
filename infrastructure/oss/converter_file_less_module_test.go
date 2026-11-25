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

package oss

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestProcessScanResults_AffectedFilePath(t *testing.T) {
	tests := []struct {
		name              string
		displayTargetFile string
		fileExistsOnDisk  bool
		expectedPath      string
	}{
		{
			name:              "module with build file on disk",
			displayTargetFile: "cli/handwritingScanner/build.gradle.kts",
			fileExistsOnDisk:  true,
			expectedPath:      "cli/handwritingScanner/build.gradle.kts",
		},
		{
			name:              "declared module without build file, nested",
			displayTargetFile: "cli/build.gradle",
			fileExistsOnDisk:  false,
			expectedPath:      "cli/build.gradle",
		},
		{
			name:              "declared module without build file, top level",
			displayTargetFile: "frontend/build.gradle",
			fileExistsOnDisk:  false,
			expectedPath:      "frontend/build.gradle",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			workDir := t.TempDir()
			if tc.fileExistsOnDisk {
				require.NoError(t, os.MkdirAll(filepath.Join(workDir, filepath.Dir(tc.displayTargetFile)), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(workDir, tc.displayTargetFile), []byte("plugins {}"), 0o644))
			}
			scanOutput := fmt.Sprintf(`[{"path":%q,"displayTargetFile":%q,"projectName":"p","packageManager":"gradle","vulnerabilities":[`+
				`{"id":"SNYK-1","packageName":"trove4j","name":"trove4j","version":"1.0","severity":"high","title":"t",`+
				`"from":["a@1","trove4j@1.0"],"upgradePath":[],"identifiers":{"CVE":[],"CWE":[]},"cvssScore":1}]}]`,
				workDir, tc.displayTargetFile)

			learnService := mock_learn.NewMockService(gomock.NewController(t))
			learnService.EXPECT().GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
			ctx := ctx2.NewContextWithEngine(context.Background(), engine)
			ctx = ctx2.NewContextWithWorkDirAndFilePath(ctx, types.FilePath(workDir), types.FilePath(workDir))
			ctx = EnrichContextForTest(t, ctx, engine, workDir)

			issues, err := ProcessScanResults(ctx, []byte(scanOutput), error_reporting.NewTestErrorReporter(engine), learnService, map[string][]types.Issue{}, false, "html")

			require.NoError(t, err)
			require.Len(t, issues, 1)
			assert.Equal(t, types.FilePath(filepath.Join(workDir, tc.expectedPath)), issues[0].GetAffectedFilePath())
		})
	}
}

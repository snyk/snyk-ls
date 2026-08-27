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

package code

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/snyk/code-client-go/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestFakeCodeScannerClient_UploadAndAnalyze_ArtifactURIsRelativeToScanRoot mirrors the
// path shape the reserved-device-filenames BDD scenario scans: a file directly under the
// scan root plus a file nested under scripts/build/. The scan root must come from the
// scan.Target the real caller passes, not from a heuristic over the file list, or an
// artifact URI can end up empty and get published as a diagnostic on the folder itself.
func TestFakeCodeScannerClient_UploadAndAnalyze_ArtifactURIsRelativeToScanRoot(t *testing.T) {
	scanRoot := t.TempDir()
	testutil.InitGitRepoWithFiles(t, types.FilePath(scanRoot), map[string]string{"README.md": "test repo\n"})
	rootFile := filepath.Join(scanRoot, "Known.java")
	nestedFile := filepath.Join(scanRoot, "scripts", "build", "prn.sh")

	target, err := scan.NewRepositoryTarget(scanRoot)
	require.NoError(t, err)

	files := make(chan string, 2)
	files <- rootFile
	files <- nestedFile
	close(files)

	fake := &FakeCodeScannerClient{}
	response, _, err := fake.UploadAndAnalyze(context.Background(), "request-id", target, files, nil)
	require.NoError(t, err)
	require.Len(t, response.Sarif.Runs, 1)

	var uris []string
	for _, result := range response.Sarif.Runs[0].Results {
		for _, loc := range result.Locations {
			uris = append(uris, loc.PhysicalLocation.ArtifactLocation.URI)
		}
	}

	assert.Contains(t, uris, "Known.java")
	assert.Contains(t, uris, "scripts/build/prn.sh")
	assert.NotContains(t, uris, "")
	assert.NotContains(t, uris, ".")
}

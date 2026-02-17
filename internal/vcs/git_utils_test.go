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

package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestGitRepoRoot_AtRepoRoot(t *testing.T) {
	repoPath := types.FilePath(t.TempDir())
	initGitRepo(t, repoPath, false)

	root, err := GitRepoRoot(repoPath)

	require.NoError(t, err)
	assert.Equal(t, repoPath, root)
}

func TestGitRepoRoot_FromSubfolder(t *testing.T) {
	repoPath := types.FilePath(t.TempDir())
	initGitRepo(t, repoPath, false)

	subfolder := filepath.Join(string(repoPath), "some", "nested", "subfolder")
	require.NoError(t, os.MkdirAll(subfolder, 0o755))

	root, err := GitRepoRoot(types.FilePath(subfolder))

	require.NoError(t, err)
	assert.Equal(t, repoPath, root)
}

func TestGitRepoRoot_NotAGitRepo(t *testing.T) {
	notARepo := types.FilePath(t.TempDir())

	_, err := GitRepoRoot(notARepo)

	assert.Error(t, err)
}

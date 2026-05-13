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

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func TestResolveCliDir_NoCacheEnv(t *testing.T) {
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", "")

	dir, cleanup := resolveCliDir()

	assert.NotEmpty(t, dir)
	_, err := os.Stat(dir)
	assert.NoError(t, err, "temp dir must exist before cleanup")

	cleanup()
	_, err = os.Stat(dir)
	assert.True(t, os.IsNotExist(err), "cleanup must remove the temp dir")
}

func TestResolveCliDir_WithCacheEnv(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", cacheDir)

	dir, cleanup := resolveCliDir()
	defer cleanup()

	assert.Equal(t, cacheDir, dir, "must return the env-specified cache dir")

	cleanup()
	_, err := os.Stat(cacheDir)
	assert.NoError(t, err, "cleanup must be a no-op for a pre-configured cache dir")
}

func TestResolveCliDir_WithCacheEnvCreatesDir(t *testing.T) {
	parent := t.TempDir()
	cacheDir := filepath.Join(parent, "cli-cache")
	t.Setenv("SNYK_LS_CLI_CACHE_DIR", cacheDir)

	dir, cleanup := resolveCliDir()
	defer cleanup()

	assert.Equal(t, cacheDir, dir)
	_, err := os.Stat(cacheDir)
	assert.NoError(t, err, "resolveCliDir must create the cache dir when it does not exist")
}

func TestCloneRepoOnceCached_NoCacheRoot_ReturnsError(t *testing.T) {
	// With empty cacheRoot, falls through to cloneRepoOnce which needs network.
	// We can't test that path here without network — covered by smoke TestMain.
	t.Skip("no-cache-root path requires network; tested via SMOKE_TESTS=1")
}

func TestCloneRepoOnceCached_CacheHit(t *testing.T) {
	cacheRoot := t.TempDir()
	subdir := "myrepo"
	commit := "abc1234"

	// Pre-populate the cache at cacheRoot/myrepo
	cached := filepath.Join(cacheRoot, subdir)
	require.NoError(t, os.MkdirAll(cached, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(cached, "sentinel"), []byte("cached"), 0o644))

	result, err := cloneRepoOnceCached("prefix-*", cacheRoot, "https://example.invalid/repo.git", subdir, commit)

	require.NoError(t, err)
	assert.Equal(t, types.FilePath(cacheRoot), result, "cache hit must return cacheRoot as base")

	// Confirm the cached dir is intact (no network call was made)
	_, err = os.Stat(filepath.Join(cacheRoot, subdir, "sentinel"))
	assert.NoError(t, err)
}

func TestCloneRepoOnceCached_NoCacheRootPassesThrough(t *testing.T) {
	// When cacheRoot is "", the function must return the same result as cloneRepoOnce.
	// Use a local bare git repo so no network access is required.
	bareDir := t.TempDir()
	initCmd := exec.Command("git", "init", "--bare", "repo.git")
	initCmd.Dir = bareDir
	require.NoError(t, initCmd.Run())

	repoURL := filepath.Join(bareDir, "repo.git")

	result, err := cloneRepoOnceCached("prefix-*", "", repoURL, "repo", "")
	require.NoError(t, err)
	defer os.RemoveAll(string(result))

	clonedRepo := filepath.Join(string(result), "repo")
	_, err = os.Stat(clonedRepo)
	assert.NoError(t, err, "cloned repo directory must exist")
}

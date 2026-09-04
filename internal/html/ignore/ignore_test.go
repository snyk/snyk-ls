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

package ignore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
)

func TestCanCreateIgnore(t *testing.T) {
	t.Run("empty content root", func(t *testing.T) {
		assert.False(t, CanCreateIgnore(""))
	})

	t.Run("not a git repo", func(t *testing.T) {
		dir := t.TempDir()
		assert.False(t, CanCreateIgnore(dir))
	})

	t.Run("git repo without origin remote", func(t *testing.T) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		assert.False(t, CanCreateIgnore(dir))
	})

	t.Run("git repo with origin remote", func(t *testing.T) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		runGit(t, dir, "remote", "add", "origin", "https://github.com/org/repo.git")
		assert.True(t, CanCreateIgnore(dir))
	})

	t.Run("subfolder of git repo with origin", func(t *testing.T) {
		dir := t.TempDir()
		initGitRepo(t, dir)
		runGit(t, dir, "remote", "add", "origin", "https://github.com/org/repo.git")
		subdir := filepath.Join(dir, "nested", "package")
		require.NoError(t, os.MkdirAll(subdir, 0755))
		assert.True(t, CanCreateIgnore(subdir))
	})
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "--initial-branch=main")
	runGit(t, dir, "config", "commit.gpgsign", "false")
	seed := filepath.Join(dir, "seed.txt")
	require.NoError(t, os.WriteFile(seed, []byte("seed"), 0600))
	runGit(t, dir, "add", "seed.txt")
	cmd := gitCommandForTestRepo(dir, "commit", "-m", "init")
	cmd.Env = append(cmd.Env,
		"GIT_AUTHOR_NAME=Snyk LS Test",
		"GIT_AUTHOR_EMAIL=snyk-ls-test@example.invalid",
		"GIT_COMMITTER_NAME=Snyk LS Test",
		"GIT_COMMITTER_EMAIL=snyk-ls-test@example.invalid",
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := gitCommandForTestRepo(dir, args...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
}

func gitCommandForTestRepo(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	return cmd
}

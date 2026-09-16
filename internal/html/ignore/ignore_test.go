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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCanCreateIgnore(t *testing.T) {
	t.Run("empty content root", func(t *testing.T) {
		assert.False(t, CanCreateIgnore("", nil))
	})

	t.Run("not a git repo", func(t *testing.T) {
		dir := t.TempDir()
		assert.False(t, CanCreateIgnore(dir, nil))
	})

	t.Run("git repo without origin remote", func(t *testing.T) {
		dir := t.TempDir()
		testsupport.InitTestGitRepo(t, dir)
		assert.False(t, CanCreateIgnore(dir, nil))
	})

	t.Run("git repo with origin remote", func(t *testing.T) {
		dir := t.TempDir()
		testsupport.InitTestGitRepoWithOrigin(t, dir, "")
		assert.True(t, CanCreateIgnore(dir, nil))
	})

	t.Run("subfolder of git repo with origin", func(t *testing.T) {
		dir := t.TempDir()
		testsupport.InitTestGitRepoWithOrigin(t, dir, "")
		subdir := filepath.Join(dir, "nested", "package")
		require.NoError(t, os.MkdirAll(subdir, 0755))
		assert.True(t, CanCreateIgnore(subdir, nil))
	})

	t.Run("non-git folder with remote-repo-url override configured", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		dir := t.TempDir()
		types.SetFolderUserSetting(engine.GetConfiguration(), types.FilePath(dir), types.SettingAdditionalParameters,
			[]string{"--remote-repo-url=https://github.com/example/repo.git"})
		assert.True(t, CanCreateIgnore(dir, testutil.DefaultConfigResolver(engine)))
	})

	t.Run("non-git folder without override still returns false", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		dir := t.TempDir()
		assert.False(t, CanCreateIgnore(dir, testutil.DefaultConfigResolver(engine)))
	})

	t.Run("non-git folder with global remote-repo-url override configured", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		dir := t.TempDir()
		types.SetGlobalDeferredFolderScope(engine.GetConfiguration(), types.SettingCliAdditionalOssParameters,
			[]string{"--remote-repo-url=https://github.com/example/repo.git"})
		assert.True(t, CanCreateIgnore(dir, testutil.DefaultConfigResolver(engine)))
	})
}

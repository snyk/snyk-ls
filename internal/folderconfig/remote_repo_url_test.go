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

package folderconfig

import (
	"os"
	"os/exec"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
)

// newTestConfigResolver builds a *types.ConfigResolver with prefix-key resolution wired,
// mirroring the setup types_test.newResolverWithConfig uses (that helper lives in an
// unexported test-only package and can't be imported here).
func newTestConfigResolver(t *testing.T) (*types.ConfigResolver, configuration.Configuration) {
	t.Helper()
	conf := configuration.NewWithOpts()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	prefixKeyResolver := configresolver.New(conf, fm)
	logger := zerolog.Nop()
	resolver := types.NewConfigResolver(&logger)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, conf, fm)
	return resolver, conf
}

func gitCommandForRemoteRepoUrlTest(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", testsupport.GitUnsigned(args...)...)
	cmd.Dir = dir
	cmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	return cmd
}

// initGitRepoWithRemote creates a throwaway Git repository with an "origin" remote,
// the same shape code.TempWorkdirWithIssues builds for its fixtures.
func initGitRepoWithRemote(t *testing.T, dir string, remoteUrl string) {
	t.Helper()
	_, err := gitCommandForRemoteRepoUrlTest(dir, "init").Output()
	require.NoError(t, err)
	_, err = gitCommandForRemoteRepoUrlTest(dir, "config", "remote.origin.url", remoteUrl).Output()
	require.NoError(t, err)
}

func Test_RemoteRepoUrlOverride(t *testing.T) {
	const override = "https://mainframe.example/payroll"

	t.Run("folder-only override", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}
		types.SetFolderUserSetting(conf, folderPath, types.SettingAdditionalParameters,
			[]string{"--remote-repo-url=" + override})

		assert.Equal(t, override, RemoteRepoUrlOverride(resolver, fc))
	})

	t.Run("global-only override", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}
		types.SetGlobalDeferredFolderScope(conf, types.SettingCliAdditionalOssParameters,
			[]string{"--remote-repo-url", override})

		assert.Equal(t, override, RemoteRepoUrlOverride(resolver, fc))
	})

	t.Run("folder override wins when both are set", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}
		types.SetGlobalDeferredFolderScope(conf, types.SettingCliAdditionalOssParameters,
			[]string{"--remote-repo-url=https://global.example/wrong"})
		types.SetFolderUserSetting(conf, folderPath, types.SettingAdditionalParameters,
			[]string{"--remote-repo-url=" + override})

		assert.Equal(t, override, RemoteRepoUrlOverride(resolver, fc))
	})

	t.Run("absent", func(t *testing.T) {
		resolver, _ := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}

		assert.Empty(t, RemoteRepoUrlOverride(resolver, fc))
	})

	t.Run("nil folder config falls back to the global override", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		types.SetGlobalDeferredFolderScope(conf, types.SettingCliAdditionalOssParameters,
			[]string{"--remote-repo-url=" + override})

		assert.Equal(t, override, RemoteRepoUrlOverride(resolver, nil))
	})

	t.Run("nil resolver", func(t *testing.T) {
		assert.Empty(t, RemoteRepoUrlOverride(nil, &types.FolderConfig{FolderPath: types.FilePath(t.TempDir())}))
	})

	t.Run("space-separated flag form", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}
		types.SetFolderUserSetting(conf, folderPath, types.SettingAdditionalParameters,
			[]string{"--remote-repo-url", override})

		assert.Equal(t, override, RemoteRepoUrlOverride(resolver, fc))
	})
}

func Test_RepoUrlForIgnores(t *testing.T) {
	t.Run("override takes precedence", func(t *testing.T) {
		resolver, conf := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		initGitRepoWithRemote(t, string(folderPath), "https://dummy.dummy.io/gitty.git")
		fc := &types.FolderConfig{FolderPath: folderPath}
		types.SetFolderUserSetting(conf, folderPath, types.SettingAdditionalParameters,
			[]string{"--remote-repo-url=https://mainframe.example/payroll"})

		url, err := RepoUrlForIgnores(resolver, fc)

		require.NoError(t, err)
		assert.Equal(t, "https://mainframe.example/payroll", url)
	})

	t.Run("falls back to the Git remote", func(t *testing.T) {
		resolver, _ := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		initGitRepoWithRemote(t, string(folderPath), "https://dummy.dummy.io/gitty.git")
		fc := &types.FolderConfig{FolderPath: folderPath}

		url, err := RepoUrlForIgnores(resolver, fc)

		require.NoError(t, err)
		assert.Equal(t, "https://dummy.dummy.io/gitty.git", url)
	})

	t.Run("errors when neither is available", func(t *testing.T) {
		resolver, _ := newTestConfigResolver(t)
		folderPath := types.FilePath(t.TempDir())
		fc := &types.FolderConfig{FolderPath: folderPath}

		_, err := RepoUrlForIgnores(resolver, fc)

		require.Error(t, err)
	})
}

func Test_extractFlagValue(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flag     string
		expected string
	}{
		{
			name:     "equals form",
			args:     []string{"--all-projects", "--remote-repo-url=https://github.com/example/repo.git"},
			flag:     "--remote-repo-url",
			expected: "https://github.com/example/repo.git",
		},
		{
			name:     "space-separated form",
			args:     []string{"--remote-repo-url", "https://github.com/example/repo.git"},
			flag:     "--remote-repo-url",
			expected: "https://github.com/example/repo.git",
		},
		{
			name:     "flag not present",
			args:     []string{"--all-projects"},
			flag:     "--remote-repo-url",
			expected: "",
		},
		{
			name:     "space-separated form missing value",
			args:     []string{"--remote-repo-url"},
			flag:     "--remote-repo-url",
			expected: "",
		},
		{
			name:     "empty args",
			args:     []string{},
			flag:     "--remote-repo-url",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractFlagValue(tt.args, tt.flag))
		})
	}
}

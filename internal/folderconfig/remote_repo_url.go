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
	"io"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/internal/types"
)

// RepoUrlUnavailableRemedy is the user-facing remedy appended to error messages when
// neither a Git remote nor a --remote-repo-url override can be resolved for a folder.
const RepoUrlUnavailableRemedy = "add a Git remote to the folder, or set --remote-repo-url in Additional parameters, then rescan"

// RemoteRepoUrlOverride returns the --remote-repo-url value from the folder's Additional
// Parameters, or "". IntelliJ stores them per folder; VS Code sends one global string that
// applyCliConfig files under SettingCliAdditionalOssParameters. Both are read; per-folder wins.
func RemoteRepoUrlOverride(resolver types.ConfigResolverInterface, fc *types.FolderConfig) string {
	if resolver == nil {
		return ""
	}
	if fc != nil {
		if value := remoteRepoUrlFromArgs(resolver.GetStringSlice(types.SettingAdditionalParameters, fc)); value != "" {
			return value
		}
	}
	return remoteRepoUrlFromArgs(resolver.GetStringSlice(types.SettingCliAdditionalOssParameters, fc))
}

// RepoUrlForIgnores is the URL ignores for this folder are keyed on: the override if set,
// else the Git origin URL (the resolver GAF's ignore workflow uses). Error if neither.
func RepoUrlForIgnores(resolver types.ConfigResolverInterface, fc *types.FolderConfig) (string, error) {
	if override := RemoteRepoUrlOverride(resolver, fc); override != "" {
		return override, nil
	}
	var contentRoot string
	if fc != nil {
		contentRoot = string(fc.GetFolderPath())
	}
	return git.RepoUrlFromDir(contentRoot)
}

// remoteRepoUrlFromArgs parses args the way the CLI does, so repeated flags resolve last-wins
// and unrelated Additional Parameters are ignored. An empty value counts as not set.
func remoteRepoUrlFromArgs(args []string) string {
	fs := pflag.NewFlagSet("additional-parameters", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist = pflag.ParseErrorsAllowlist{UnknownFlags: true}
	fs.SetOutput(io.Discard)
	// pflag aborts parsing on an undefined --help/-h; defining it lets parsing continue.
	fs.BoolP("help", "h", false, "")
	var remoteRepoUrl string
	fs.StringVar(&remoteRepoUrl, configuration.FLAG_REMOTE_REPO_URL, "", "")
	_ = fs.Parse(args)
	return remoteRepoUrl
}

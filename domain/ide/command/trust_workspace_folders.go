/*
 * © 2023 Snyk Limited
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

package command

import (
	"context"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type trustWorkspaceFoldersCommand struct {
	command        types.CommandData
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
}

func (cmd *trustWorkspaceFoldersCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *trustWorkspaceFoldersCommand) Execute(ctx context.Context) (any, error) {
	if !cmd.configResolver.GetBool(types.SettingTrustEnabled, nil) {
		return nil, nil
	}

	ws := config.GetWorkspace(cmd.engine.GetConfiguration())
	if ws == nil {
		return nil, nil
	}

	_, untrusted := ws.GetFolderTrust()
	if len(untrusted) == 0 {
		return nil, nil
	}

	// An optional folder-path argument scopes the action to a single folder, so the
	// tree-view banner's per-folder Trust button trusts just that folder (IDE-1882).
	// With no argument we trust every untrusted folder (the original behavior, used
	// by the "trust all" flows).
	toTrust := untrusted
	if path, ok := folderPathArg(cmd.command.Arguments); ok {
		toTrust = filterFoldersByPath(untrusted, path)
		if len(toTrust) == 0 {
			// The banner echoes back the exact path the builder emitted, so a
			// non-empty arg should always match an untrusted folder. A zero match
			// means the client sent a path that doesn't equal any untrusted folder
			// (e.g. it normalized a trailing slash / case / symlink before sending
			// it back) — the Trust button would otherwise silently do nothing, so
			// log it to make that failure mode diagnosable. (IDE-1882)
			cmd.engine.GetLogger().Debug().
				Str("method", "trustWorkspaceFoldersCommand.Execute").
				Str("path", string(path)).
				Msg("trust folder-path argument matched no untrusted folder; nothing trusted")
			return nil, nil
		}
	}

	// TrustFoldersAndScan persists the trusted folders, sends the SnykTrustedFolders
	// notification, and triggers a scan of each newly trusted folder. The tree-view
	// banner is now the sole trust prompt (the modal window/showMessageRequest dialog
	// was removed), so trusting from it must also scan. (IDE-1882)
	//
	// Detach from the command's context: the command executor cancels ctx when
	// Execute returns, which would kill the un-awaited scan goroutine that
	// TrustFoldersAndScan spawns (and the tree only re-renders, hiding the banner,
	// once that scan produces state changes). WithoutCancel keeps any context
	// values while dropping the cancellation, matching the context.Background()
	// the other scan commands use for the same reason.
	ws.TrustFoldersAndScan(context.WithoutCancel(ctx), toTrust)
	return nil, nil
}

// folderPathArg extracts an optional folder-path string from the command
// arguments. Returns ("", false) when no usable path argument is present.
func folderPathArg(args []any) (types.FilePath, bool) {
	if len(args) == 0 {
		return "", false
	}
	path, ok := args[0].(string)
	if !ok || path == "" {
		return "", false
	}
	return types.FilePath(path), true
}

// filterFoldersByPath returns the folders whose path exactly matches the given
// path. The banner sends back the same path string it received in FolderPaths,
// so an exact match is sufficient.
func filterFoldersByPath(folders []types.Folder, path types.FilePath) []types.Folder {
	var matched []types.Folder
	for _, f := range folders {
		if f.Path() == path {
			matched = append(matched, f)
		}
	}
	return matched
}

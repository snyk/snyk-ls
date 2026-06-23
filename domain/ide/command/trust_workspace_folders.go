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
	// Safety: a present-but-malformed arg (wrong type, empty string) must NOT fall
	// through to trust-all — it takes the safe path (trust nothing). Only a truly
	// absent argument (len==0) triggers the trust-all behaviour.
	toTrust := untrusted
	if path, argPresent, ok := folderPathArg(cmd.command.Arguments); argPresent {
		if !ok {
			// Arg was present but malformed (wrong type or empty string) — safer to
			// do nothing than to trust all folders the user didn't explicitly choose.
			// (nil, nil) is the correct no-op return for this command bus: the
			// executor does not surface errors to the user; Warn is the observable signal.
			cmd.engine.GetLogger().Warn().
				Str("method", "trustWorkspaceFoldersCommand.Execute").
				Msg("trust folder-path argument present but malformed; nothing trusted")
			return nil, nil
		}
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
// arguments. It returns three values:
//   - path: the extracted FilePath (valid only when ok is true)
//   - argPresent: true when args is non-empty (an argument was provided)
//   - ok: true when the argument is a non-empty string
//
// Callers must distinguish "no argument" (argPresent=false → trust all) from
// "malformed argument" (argPresent=true, ok=false → trust nothing).
func folderPathArg(args []any) (path types.FilePath, argPresent bool, ok bool) {
	if len(args) == 0 {
		return "", false, false
	}
	s, isString := args[0].(string)
	if !isString || s == "" {
		return "", true, false
	}
	return types.FilePath(s), true, true
}

// filterFoldersByPath returns the folders whose normalised path matches the
// given path after PathKey normalisation on both sides. PathKey trims trailing
// slashes and runs filepath.Clean, so the IDE can safely round-trip paths with
// or without a trailing slash (e.g. "/repo/a/" matches folder "/repo/a").
func filterFoldersByPath(folders []types.Folder, path types.FilePath) []types.Folder {
	normPath := types.PathKey(path)
	var matched []types.Folder
	for _, f := range folders {
		if types.PathKey(f.Path()) == normPath {
			matched = append(matched, f)
		}
	}
	return matched
}

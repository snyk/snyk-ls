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

package command

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// remediationFixFolderCommand implements workspace/executeCommand for
// snyk.remediationAgent.fixFolder. It validates the folder URI argument, runs
// the fix workflow directly in that folder (which is already an isolated git
// worktree created by the caller), and returns a FolderFixResult with one entry
// per changed file. The command is blocking — the caller waits for the full fix
// duration. It does NOT send workspace/applyEdit; the daemon lands changes by
// copying each WorktreePath over the corresponding workspace file.
type remediationFixFolderCommand struct {
	command   types.CommandData
	provider  remediation.FolderRemediator // nil when feature is off
	workspace types.Workspace              // nil when no workspace is registered
	logger    zerolog.Logger
}

func (cmd *remediationFixFolderCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *remediationFixFolderCommand) Execute(ctx context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) != 1 && len(args) != 2 {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: expected one folder URI argument and an optional workspace root URI, got %d", len(args))
	}
	folderURIStr, ok := args[0].(string)
	if !ok || folderURIStr == "" {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: folder URI argument must be a non-empty string")
	}

	path := uri.PathFromUri(sglsp.DocumentURI(folderURIStr))
	pathStr := string(path)
	if pathStr == "" || !filepath.IsAbs(pathStr) {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: folder URI did not resolve to an absolute path: %q", folderURIStr)
	}
	if !uri.IsDirectory(path) {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: folder does not exist or is not a directory: %q", pathStr)
	}

	if cmd.provider == nil {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: remediation agent is not enabled")
	}

	findingIDs, scoped, err := cmd.resolveScope(args)
	if err != nil {
		return nil, err
	}
	// Remy reads an empty issue-ids value as no filter at all, so a folder with
	// nothing net-new must skip the run rather than hand it the whole folder.
	if scoped && len(findingIDs) == 0 {
		return types.FolderFixResult{Files: []types.FolderFixFileResult{}}, nil
	}

	files, err := cmd.provider.FixFolder(ctx, path, findingIDs)
	if err != nil {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: %w", err)
	}
	// Ensure Files is never nil so JSON marshals as [] not null.
	if files == nil {
		files = []types.FolderFixFileResult{}
	}
	return types.FolderFixResult{Files: files}, nil
}

// resolveScope fails open to an unscoped run when the root matches no registered
// folder, delta is off, or there is no baseline yet.
func (cmd *remediationFixFolderCommand) resolveScope(args []any) (findingIDs []string, scoped bool, err error) {
	if len(args) < 2 {
		return nil, false, nil
	}
	rootURIStr, ok := args[1].(string)
	if !ok || rootURIStr == "" {
		return nil, false, fmt.Errorf("snyk.remediationAgent.fixFolder: workspace root URI argument must be a non-empty string")
	}

	folder := cmd.folderForRoot(uri.PathFromUri(sglsp.DocumentURI(rootURIStr)))
	if folder == nil {
		cmd.logger.Warn().Str("root", rootURIStr).Msg("snyk.remediationAgent.fixFolder: no registered folder for the given workspace root, running unscoped")
		return nil, false, nil
	}
	if !folder.IsDeltaAppliedForProduct(product.ProductCode) {
		if folder.IsDeltaFindingsEnabled() {
			cmd.logger.Warn().Str("root", rootURIStr).Msg("snyk.remediationAgent.fixFolder: delta scoping requested but no baseline is available, running unscoped")
		}
		return nil, false, nil
	}
	fip, ok := folder.(snyk.FilteringIssueProvider)
	if !ok {
		cmd.logger.Warn().Str("root", rootURIStr).Msg("snyk.remediationAgent.fixFolder: folder cannot filter its findings, running unscoped")
		return nil, false, nil
	}
	// The display filter drops non-net-new findings when delta applies, so this is
	// exactly the net-new set the developer was shown.
	ids, withoutID := codeFindingIDs(fip.FilterIssues(fip.Issues(), folder.DisplayableIssueTypes()))
	if withoutID > 0 {
		cmd.logger.Warn().Str("root", rootURIStr).Int("findingsWithoutID", withoutID).
			Msg("snyk.remediationAgent.fixFolder: some net-new findings have no asset fingerprint, which Snyk Code only emits for a repository with an origin remote, so remy cannot target them")
	}
	cmd.logger.Info().Str("root", rootURIStr).Int("netNewFindings", len(ids)).
		Msg("snyk.remediationAgent.fixFolder: scoping the fix to the folder's net-new findings")
	return ids, true, nil
}

// Exact match, not containment: containment would also hit a parent folder and
// scope the run to a different folder's net-new set.
func (cmd *remediationFixFolderCommand) folderForRoot(root types.FilePath) types.Folder {
	if cmd.workspace == nil {
		return nil
	}
	// PathKey is how a folder's own path was normalized when it was registered.
	key := types.PathKey(root)
	for _, folder := range cmd.workspace.Folders() {
		if types.PathKey(folder.Path()) == key {
			return folder
		}
	}
	return nil
}

// For Snyk Code the finding identifier is the asset fingerprint remy matches
// issue-ids against, so it needs no translation.
func codeFindingIDs(issues snyk.IssuesByFile) (ids []string, withoutID int) {
	ids = make([]string, 0, len(issues))
	for _, fileIssues := range issues {
		for _, issue := range fileIssues {
			if issue.GetProduct() != product.ProductCode {
				continue
			}
			if id := issue.GetFindingId(); id != "" {
				ids = append(ids, id)
			} else {
				withoutID++
			}
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids), withoutID
}

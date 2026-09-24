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

// netNewProvider is the concrete folder's net-new accessor, matching
// domain/snyk/delta.Provider.
type netNewProvider interface {
	GetDelta(p product.Product) snyk.IssuesByFile
}

// resolveScope reads the optional workspace-root argument and returns the native
// finding identifiers the run must be restricted to. scoped reports whether any
// restriction applies, which is what separates an empty set ("fix nothing") from
// an absent one ("fix everything"). A root that resolves to no registered folder,
// a folder with delta off, or one with no baseline yet all run unscoped.
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
	// types.Folder carries the delta predicates but not the net-new set itself,
	// so the concrete folder's own accessor is reached structurally rather than
	// by widening that interface and regenerating its mock.
	deltaProvider, ok := folder.(netNewProvider)
	if !ok {
		cmd.logger.Warn().Str("root", rootURIStr).Msg("snyk.remediationAgent.fixFolder: folder cannot report its net-new findings, running unscoped")
		return nil, false, nil
	}
	ids := codeFindingIDs(deltaProvider.GetDelta(product.ProductCode))
	cmd.logger.Info().Str("root", rootURIStr).Int("netNewFindings", len(ids)).
		Msg("snyk.remediationAgent.fixFolder: scoping the fix to the folder's net-new findings")
	return ids, true, nil
}

// folderForRoot returns the registered folder whose path is exactly root.
// Containment matching is deliberately not used: it would also hit a parent
// folder and scope the run to a different folder's net-new set.
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

// codeFindingIDs collects the Snyk Code finding identifiers from issues. For that
// product the identifier is the asset fingerprint remy matches issue-ids against,
// so it needs no translation. Issues carrying none are dropped.
func codeFindingIDs(issues snyk.IssuesByFile) []string {
	ids := make([]string, 0, len(issues))
	for _, fileIssues := range issues {
		for _, issue := range fileIssues {
			if id := issue.GetFindingId(); id != "" {
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

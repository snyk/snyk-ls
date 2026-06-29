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
	"errors"
	"fmt"
	"path/filepath"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

// remediationFixFolderCommand implements workspace/executeCommand for
// snyk.remediationAgent.fixFolder. It validates the folder URI argument, runs
// the fix workflow directly in that folder (which is already an isolated git
// worktree created by the caller), and delivers any resulting edits to the
// client via workspace/applyEdit. The command is blocking — the caller waits
// for the full fix duration.
type remediationFixFolderCommand struct {
	command  types.CommandData
	notifier notification.Notifier
	provider remediation.FolderRemediator // nil when feature is off
	engine   workflow.Engine
}

func (cmd *remediationFixFolderCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *remediationFixFolderCommand) Execute(ctx context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) != 1 {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: expected exactly one folder URI argument, got %d", len(args))
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

	if cmd.engine != nil {
		key := types.SettingClientCapabilities
		capabilities, _ := cmd.engine.GetConfiguration().Get(key).(types.ClientCapabilities)
		if !capabilities.Workspace.ApplyEdit {
			return nil, errors.New("snyk.remediationAgent.fixFolder: client does not support workspace/applyEdit capability")
		}
	}

	edit, err := cmd.provider.FixFolder(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("snyk.remediationAgent.fixFolder: %w", err)
	}
	if edit == nil || len(edit.Changes) == 0 {
		return nil, nil
	}

	cmd.notifier.Send(types.ApplyWorkspaceEditParams{
		Label: "Snyk Remediation Agent fix",
		Edit:  converter.ToWorkspaceEdit(edit),
	})
	return nil, nil
}

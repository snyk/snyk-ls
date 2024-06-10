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
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type fixCodeIssue struct {
	command       snyk.CommandData
	issueProvider snyk.IssueProvider
	notifier      notification.Notifier
	logger        *zerolog.Logger
}

func (cmd *fixCodeIssue) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *fixCodeIssue) Execute(_ context.Context) (any, error) {
	if !config.CurrentConfig().ClientCapabilities().Workspace.ApplyEdit {
		cmd.logger.Error().Msg("Client doesn't support 'workspace/applyEdit' capability, skipping fix attempt.")
		return nil, errors.New("Client doesn't support 'workspace/applyEdit' capability.")
	}

	args := cmd.command.Arguments
	codeActionId, err := uuid.Parse(args[0].(string))
	if err != nil {
		return nil, errors.New("Failed to parse code action id.")
	}
	issuePath := args[1].(string)
	issueRange := cmd.toRange(args[2])

	issues := cmd.issueProvider.IssuesForRange(issuePath, issueRange)
	for i := range issues {
		for _, action := range issues[i].CodeActions {
			if action.Uuid == nil || *action.Uuid != codeActionId {
				continue
			}

			// execute autofix codeaction
			edit := (*action.DeferredEdit)()
			if edit == nil {
				cmd.logger.Info().Msg("No fix could be computed.")
				return nil, nil
			}

			cmd.notifier.Send(lsp.ApplyWorkspaceEditParams{
				Label: "Snyk Code fix",
				Edit:  converter.ToWorkspaceEdit(edit),
			})

			// reset codelenses
			issues[i].CodelensCommands = nil

			// Give client some time to apply edit, then refresh code lenses to hide stale codelens for the fixed issue
			time.Sleep(1 * time.Second)
			cmd.notifier.Send(lsp.CodeLensRefresh{})
			return nil, nil
		}
	}

	return nil, errors.New("Failed to find autofix code action.")
}

type RangeDto = map[string]interface{}
type RangePositionDto = map[string]interface{}

func (cmd *fixCodeIssue) toRange(rangeArg any) snyk.Range {
	dto := rangeArg.(RangeDto)
	startPos := dto["Start"]
	endPos := dto["End"]
	startLine := startPos.(RangePositionDto)["Line"].(float64)
	startChar := startPos.(RangePositionDto)["Character"].(float64)
	endLine := endPos.(RangePositionDto)["Line"].(float64)
	endChar := endPos.(RangePositionDto)["Character"].(float64)

	snykRange := snyk.Range{
		Start: snyk.Position{
			Line:      int(startLine),
			Character: int(startChar),
		},
		End: snyk.Position{
			Line:      int(endLine),
			Character: int(endChar),
		},
	}
	return snykRange
}

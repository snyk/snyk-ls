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
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type fixCodeIssue struct {
	command       types.CommandData
	issueProvider snyk.IssueProvider
	notifier      notification.Notifier
	logger        *zerolog.Logger
}

func (cmd *fixCodeIssue) Command() types.CommandData {
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
		return nil, errors.Join(err, fmt.Errorf("Failed to parse code action id."))
	}

	issueMap := cmd.issueProvider.Issues()
	for _, issues := range issueMap {
		for i := range issues {
			for _, action := range issues[i].GetCodeActions() {
				if action.GetUuid() == nil || *action.GetUuid() != codeActionId {
					continue
				}

				// execute autofix codeaction
				edit := (*action.GetDeferredEdit())()
				if edit == nil {
					cmd.logger.Debug().Msg("No fix could be computed.")
					return nil, nil
				}

				cmd.notifier.Send(types.ApplyWorkspaceEditParams{
					Label: "Snyk Code fix",
					Edit:  converter.ToWorkspaceEdit(edit),
				})

				// reset codelenses
				issues[i].SetCodelensCommands(nil)

				// Give client some time to apply edit, then refresh code lenses to hide stale codelens for the fixed issue
				time.Sleep(1 * time.Second)
				cmd.notifier.Send(types.CodeLensRefresh{})
				return nil, nil
			}
		}
	}

	return nil, errors.New("Failed to find autofix code action.")
}

type RangeDto = map[string]interface{}
type RangePositionDto = map[string]interface{}

func (cmd *fixCodeIssue) toRange(rangeArg any) (types.Range, error) {
	dto, ok := rangeArg.(RangeDto)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid range parameter")
	}
	startPos := dto["Start"]
	endPos := dto["End"]
	startPosDto, ok := startPos.(RangePositionDto)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid start position parameter")
	}
	startPosLine, ok := startPosDto["Line"].(float64)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid start position line")
	}
	startLine := startPosLine
	startChar, ok := startPosDto["Character"].(float64)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid start position character")
	}
	endPosDto, ok := endPos.(RangePositionDto)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid end position parameter")
	}

	endLine, ok := endPosDto["Line"].(float64)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid end position line")
	}
	endChar, ok := endPosDto["Character"].(float64)
	if !ok {
		return types.Range{}, fmt.Errorf("invalid end position character")
	}

	snykRange := types.Range{
		Start: types.Position{
			Line:      int(startLine),
			Character: int(startChar),
		},
		End: types.Position{
			Line:      int(endLine),
			Character: int(endChar),
		},
	}
	return snykRange, nil
}

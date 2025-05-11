/*
 * © 2025 Snyk Limited
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
	"time"

	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type applyAiFixEditCommand struct {
	command        types.CommandData
	issueProvider  snyk.IssueProvider
	notifier       notification.Notifier
	codeHttpClient SnykCodeHttpClient
	c              *config.Config
	logger         *zerolog.Logger
	apiClient      snyk_api.SnykApiClient
}

func (cmd *applyAiFixEditCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *applyAiFixEditCommand) Execute(ctx context.Context) (any, error) {
	fixId, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid edit")
	}

	htmlRenderer, err := code.GetHTMLRenderer(cmd.c, cmd.apiClient)
	if err != nil {
		cmd.logger.Debug().Str("method", "applyAiFixEditCommand.Execute").Msgf("Unable to get the htmlRenderer")
		return nil, err
	}

	workspaceEdit, err := cmd.getWorkspaceEdit(htmlRenderer, fixId)
	if err != nil {
		return nil, err
	}
	cmd.notifier.Send(types.ApplyWorkspaceEditParams{
		Label: "Snyk Code fix",
		Edit:  converter.ToWorkspaceEdit(workspaceEdit),
	})

	// send feedback asynchronously, so people can actually see the changes done by the fix
	go func() {
		err := cmd.codeHttpClient.SubmitAutofixFeedback(ctx, fixId, code.FixAppliedUserEvent)
		if err != nil {
			cmd.logger.Err(err).Str("fixId", fixId).Str("feedback", code.FixAppliedUserEvent).Msg("failed to submit autofix feedback")
		}
		issue := cmd.issueProvider.Issue(htmlRenderer.AiFixHandler.GetCurrentIssueId())
		actionCommandMap, err := cmd.autofixFeedbackActions(fixId)
		successMessage := "Congratulations! 🎉 You’ve just fixed this " + issue.GetID() + " issue."
		if err != nil {
			cmd.notifier.SendShowMessage(sglsp.Info, successMessage)
		} else {
			// sleep to give client side to actually apply & review the fix
			time.Sleep(2 * time.Second)
			cmd.notifier.Send(types.ShowMessageRequest{
				Message: successMessage + " Was this fix helpful?",
				Type:    types.Info,
				Actions: actionCommandMap,
			})
		}
	}()

	// Give client some time to apply edit, then refresh code lenses to hide stale codelens for the fixed issue
	time.Sleep(1 * time.Second)
	cmd.notifier.Send(types.CodeLensRefresh{})
	return nil, nil
}

func (cmd *applyAiFixEditCommand) getWorkspaceEdit(htmlRenderer *code.HtmlRenderer, fixId string) (*types.WorkspaceEdit, error) {
	path, diff, err := htmlRenderer.AiFixHandler.GetResults(fixId)
	if err != nil {
		cmd.logger.Error().Str("method", "applyAiFixEditCommand.getWorkspaceEdit").Msgf("Unable to get the fix for %s", fixId)
		return nil, err
	}

	workspaceEdit, err := code.CreateWorkspaceEditFromDiff(path, diff)
	if err != nil {
		return nil, fmt.Errorf("unable to create WorkspaceEdit for %s: %w", path, err)
	}
	return workspaceEdit, nil
}

func (cmd *applyAiFixEditCommand) autofixFeedbackActions(fixId string) (*data_structure.OrderedMap[types.MessageAction, types.CommandData], error) {
	createCommandData := func(feedback string) types.CommandData {
		return types.CommandData{
			Title:     types.CodeSubmitFixFeedback,
			CommandId: types.CodeSubmitFixFeedback,
			Arguments: []any{fixId, feedback},
		}
	}
	actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
	positiveFeedbackCmd := createCommandData(code.FixPositiveFeedback)
	negativeFeedbackCmd := createCommandData(code.FixNegativeFeedback)

	actionCommandMap.Add("👍", positiveFeedbackCmd)
	actionCommandMap.Add("👎", negativeFeedbackCmd)

	return actionCommandMap, nil
}

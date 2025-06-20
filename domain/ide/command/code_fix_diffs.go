/*
 * © 2023-2024 Snyk Limited
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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

type codeFixDiffs struct {
	command       types.CommandData
	srv           types.Server
	notifier      notification.Notifier
	issueProvider snyk.IssueProvider
	codeScanner   *code.Scanner
	c             *config.Config
	snykApiClient snyk_api.SnykApiClient
}

func (cmd *codeFixDiffs) Command() types.CommandData {
	return cmd.command
}

func (cmd *codeFixDiffs) Execute(_ context.Context) (any, error) {
	logger := cmd.c.Logger().With().Str("method", "codeFixDiffs.Execute").Logger()

	args := cmd.command.Arguments
	if len(args) != 1 {
		return nil, errors.New("invalid argument count")
	}

	id, ok := args[0].(string)
	if !ok {
		return nil, errors.New("failed to parse issue id")
	}

	issue := cmd.issueProvider.Issue(id)
	if issue == nil || issue.GetID() == "" {
		return nil, errors.New("failed to find issue")
	}

	htmlRenderer, err := code.GetHTMLRenderer(cmd.c, cmd.snykApiClient)
	if err != nil {
		logger.Err(err).Msg("failed to get html renderer")
		return nil, err
	}

	// This un-awaited goroutine outlives the command's execution.
	// It cannot reuse the command's context, as the command executor will cancel it when the command finishes.
	go cmd.handleResponse(context.Background(), cmd.c, issue, htmlRenderer)

	return nil, err
}

func (cmd *codeFixDiffs) handleResponse(ctx context.Context, c *config.Config, issue types.Issue, htmlRenderer *code.HtmlRenderer) {
	logger := c.Logger().With().Str("method", "codeFixDiffs.handleResponse").Logger()
	aiFixHandler := htmlRenderer.AiFixHandler

	setStateCallback := func() { SendShowDocumentRequest(ctx, logger, issue, cmd.srv) }

	aiFixHandler.SetAiFixDiffState(code.AiFixInProgress, nil, nil, setStateCallback)

	suggestions, err := cmd.codeScanner.GetAutofixDiffs(ctx, issue.GetContentRoot(), issue.GetAffectedFilePath(), issue)
	if err == nil && len(suggestions) == 0 {
		logger.Info().Msg("Autofix run successfully but there were no good fixes")
		aiFixHandler.SetAiFixDiffState(code.AiFixSuccess, nil, nil, setStateCallback)
		return
	}
	if err != nil {
		logger.Err(err).Msgf("received an error from API: %s", err.Error())
		aiFixHandler.SetAiFixDiffState(code.AiFixError, nil, err, setStateCallback)
		return
	}
	aiFixHandler.EnrichWithExplain(ctx, c, issue, suggestions)
	aiFixHandler.SetAiFixDiffState(code.AiFixSuccess, suggestions, nil, setStateCallback)
}

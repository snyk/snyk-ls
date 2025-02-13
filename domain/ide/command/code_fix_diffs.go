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
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/llm"
	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	uri2 "github.com/snyk/snyk-ls/internal/uri"
)

type codeFixDiffs struct {
	command            types.CommandData
	srv                types.Server
	notifier           notification.Notifier
	issueProvider      snyk.IssueProvider
	codeScanner        *code.Scanner
	deepCodeLLMBinding llm.DeepCodeLLMBinding
}

func (cmd *codeFixDiffs) Command() types.CommandData {
	return cmd.command
}

func (cmd *codeFixDiffs) Execute(ctx context.Context) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "codeFixDiffs.Execute").Logger()

	args := cmd.command.Arguments
	if len(args) < 3 {
		return nil, errors.New("missing required arguments")
	}

	folderURI, ok := args[0].(string)
	if !ok {
		return nil, errors.New("failed to parse folder path")
	}
	folderPath := uri2.PathFromUri(lsp.DocumentURI(folderURI))

	issueURI, ok := args[1].(string)
	if !ok {
		return nil, errors.New("failed to parse filepath")
	}

	issuePath := uri2.PathFromUri(lsp.DocumentURI(issueURI))

	relPath, err := filepath.Rel(folderPath, issuePath)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(relPath, "..") {
		return nil, errors.New("issue path is not within the folder path")
	}

	id, ok := args[2].(string)
	if !ok {
		return nil, errors.New("failed to parse issue id")
	}

	issue := cmd.issueProvider.Issue(id)
	if issue.ID == "" {
		return nil, errors.New("failed to find issue")
	}

	htmlRenderer, err := code.GetHTMLRenderer(c, cmd.deepCodeLLMBinding)
	if err != nil {
		logger.Err(err).Msg("failed to get html renderer")
		return nil, err
	}
	go cmd.handleResponse(ctx, c, folderPath, relPath, issue, htmlRenderer)

	return nil, err
}

func (cmd *codeFixDiffs) handleResponse(ctx context.Context, c *config.Config, folderPath string, relPath string, issue snyk.Issue, htmlRenderer *code.HtmlRenderer) {
	logger := c.Logger().With().Str("method", "codeFixDiffs.handleResponse").Logger()
	aiFixHandler := htmlRenderer.AiFixHandler

	setStateCallback := func() { cmd.sendShowDocumentRequest(logger, issue, cmd.srv) }

	aiFixHandler.SetAiFixDiffState(code.AiFixInProgress, nil, nil, setStateCallback)

	suggestions, err := cmd.codeScanner.GetAutofixDiffs(ctx, folderPath, relPath, issue)
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

func (cmd *codeFixDiffs) sendShowDocumentRequest(logger zerolog.Logger, issue snyk.Issue, srv types.Server) {
	snykUri := code.SnykMagnetUri(issue, code.ShowInDetailPanelIdeCommand)
	logger.Debug().
		Str("method", "code.sendShowDocumentRequest").
		Msg("showing Document")

	params := types.ShowDocumentParams{
		Uri:       lsp.DocumentURI(snykUri),
		Selection: converter.ToRange(issue.Range),
	}
	_, err := srv.Callback(context.Background(), "window/showDocument", params)
	if err != nil {
		logger.Err(err).Msgf("failed to send snyk window/showDocument callback for file %s", issue.AffectedFilePath)
	}
}

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
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)


type generateAIExplanation struct {
	command types.CommandData
	notifier notification.Notifier
	issueProvider snyk.IssueProvider
	codeScanner *code.Scanner
}

func (cmd *generateAIExplanation) Command() types.CommandData {
	return cmd.command
}

func (cmd *generateAIExplanation) Execute (ctx context.Context) (any, error) {
	logger := config.CurrentConfig().Logger().With().Str("method", "generateAIExplanation.Execute").Logger()

	args := cmd.command.Arguments
	if len(args) < 3 {
		return nil, errors.New("missing required arguments")
	}

	derivation, ok := args[0].(string)
	if !ok {
		return nil, errors.New("failed to parse derivation")
	}
	// folderPath := uri2.PathFromUri(lsp.DocumentURI(folderURI))

	ruleKey, ok := args[1].(string)
	if !ok {
		return nil, errors.New("failed to parse ruleKey")
	}

	// issuePath := uri2.PathFromUri(lsp.DocumentURI(issueURI))

	// relPath, err := filepath.Rel(folderPath, issuePath)
	// if err != nil {
	// 	return nil, err
	// }

	// if strings.HasPrefix(relPath, "..") {
	// 	return nil, errors.New("issue path is not within the folder path")
	// }

	ruleMessage, ok := args[2].(string)
	if !ok {
		return nil, errors.New("failed to parse ruleMessage")
	}

	// issue := cmd.issueProvider.Issue(id)
	// if issue.ID == "" {
	// 	return nil, errors.New("failed to find issue")
	// }

	// Now we need to call cmd.codeScanner.GetAIExplanation
	explanation, err := cmd.codeScanner.GetAIExplanation(ctx, derivation, ruleKey, ruleMessage)
	if err != nil {
		logger.Err(err).Msgf("received an error from API: %s", err.Error())
		return explanation, err
	}
	return explanation, nil
}

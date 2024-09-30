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

	"github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	uri2 "github.com/snyk/snyk-ls/internal/uri"
)

type codeFixDiffs struct {
	command       types.CommandData
	notifier      notification.Notifier
	issueProvider snyk.IssueProvider
	codeScanner   *code.Scanner
}

func (cmd *codeFixDiffs) Command() types.CommandData {
	return cmd.command
}

func (cmd *codeFixDiffs) Execute(ctx context.Context) (any, error) {
	logger := config.CurrentConfig().Logger().With().Str("method", "codeFixDiffs.Execute").Logger()
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

	suggestions, err := cmd.codeScanner.GetAutofixDiffs(ctx, folderPath, relPath, issue)
	if err != nil {
		// as long as the backend service doesn't support good error handling, we'll just log the error
		logger.Err(err).Msgf("received an error from API: %s", err.Error())
		return suggestions, nil
	}
	return suggestions, err
}

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

	"github.com/snyk/snyk-ls/domain/ide"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	uri2 "github.com/snyk/snyk-ls/internal/uri"
)

type codeFixDiffs struct {
	command       snyk.CommandData
	notifier      notification.Notifier
	issueProvider ide.IssueProvider
	codeScanner   *code.Scanner
}

func (cmd *codeFixDiffs) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *codeFixDiffs) Execute(ctx context.Context) (any, error) {
	args := cmd.command.Arguments
	if len(args) < 3 {
		return nil, errors.New("Missing required arguments.")
	}

	folderURI, ok := args[0].(string)
	if !ok {
		return nil, errors.New("Failed to parse folder path.")
	}
	folderPath := uri2.PathFromUri(lsp.DocumentURI(folderURI))

	issueURI, ok := args[1].(string)
	if !ok {
		return nil, errors.New("Failed to parse filepath.")
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
		return nil, errors.New("Failed to parse issue id.")
	}

	issue := cmd.issueProvider.Issue(id)
	if issue.ID == "" {
		return nil, errors.New("Failed to find issue.")
	}

	suggestions, err := cmd.codeScanner.GetAutoFixDiffs(ctx, folderPath, relPath, issue)
	return suggestions, err
}

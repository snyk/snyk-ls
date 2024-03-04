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

	"github.com/snyk/snyk-ls/domain/ide"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
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

	folderPath, ok := args[0].(string)
	if !ok {
		return nil, errors.New("Failed to parse folder path.")
	}

	issuePath, ok := args[1].(string)
	if !ok {
		return nil, errors.New("Failed to parse filepath.")
	}

	id, ok := args[2].(string)
	if !ok {
		return nil, errors.New("Failed to parse issue id.")
	}

	issue := cmd.issueProvider.Issue(id)
	if issue.ID == "" {
		return nil, errors.New("Failed to find issue.")
	}

	suggestions := cmd.codeScanner.GetAutoFixDiffs(ctx, folderPath, issuePath, issue)
	return suggestions, nil
}

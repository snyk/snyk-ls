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

	"github.com/snyk/snyk-ls/domain/snyk"
)

type SnykCodeHttpClient interface {
	SubmitAutofixFeedback(ctx context.Context, fixId string, positive bool) error
}

type codeFixFeedback struct {
	command   snyk.CommandData
	apiClient SnykCodeHttpClient
}

func (cmd *codeFixFeedback) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *codeFixFeedback) Execute(ctx context.Context) (any, error) {
	args := cmd.command.Arguments
	fixId := args[0].(string)
	positive := args[1].(bool)
	err := cmd.apiClient.SubmitAutofixFeedback(ctx, fixId, positive)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

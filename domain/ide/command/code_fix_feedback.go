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
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type SnykCodeHttpClient interface {
	SubmitAutofixFeedback(ctx context.Context, fixId string, positive string) error
}

type codeFixFeedback struct {
	command   types.CommandData
	apiClient SnykCodeHttpClient
}

func (cmd *codeFixFeedback) Command() types.CommandData {
	return cmd.command
}

func (cmd *codeFixFeedback) Execute(ctx context.Context) (any, error) {
	args := cmd.command.Arguments
	fixId, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("fix id should be a string")
	}
	feedback, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("feedback should be a string")
	}

	go func() {
		err := cmd.apiClient.SubmitAutofixFeedback(ctx, fixId, feedback)
		if err != nil {
			config.CurrentConfig().Logger().Err(err).Str("fixId", fixId).Str("feedback", feedback).Msg("failed to submit autofix feedback")
		}
	}()

	return nil, nil
}

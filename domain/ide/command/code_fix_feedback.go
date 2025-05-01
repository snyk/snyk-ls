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
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/llm"
	"net/url"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type codeFixFeedback struct {
	command types.CommandData
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
		c := config.CurrentConfig()
		c.Logger().Info().Str("fixId", fixId).Str("feedback", feedback).Msg("Submiting autofix feedback")
		deepCodeLLMBinding := llm.NewDeepcodeLLMBinding(
			llm.WithLogger(c.Logger()),
			llm.WithOutputFormat(llm.HTML),
			llm.WithHTTPClient(func() codeClientHTTP.HTTPClient {
				return config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient()
			}),
		)

		options := llm.AutofixFeedbackOptions{
			FixID:               fixId,
			Result:              feedback,
			Endpoint:            getAutofixFeedbackEndpoint(c),
			CodeRequestContext:  llm.CodeRequestContext{},
			IdeExtensionDetails: llm.AutofixIdeExtensionDetails{},
		}

		err := deepCodeLLMBinding.SubmitAutofixFeedback(ctx, fixId, options)
		if err != nil {
			c.Logger().Err(err).Str("fixId", fixId).Str("feedback", feedback).Msg("failed to submit autofix feedback")
		}
	}()
	return nil, nil
}

func getAutofixFeedbackEndpoint(c *config.Config) *url.URL {
	endpoint, err := url.Parse(fmt.Sprintf("%s/autofix/event", c.SnykApi()))
	if err != nil {
		return &url.URL{}
	}
	return endpoint
}

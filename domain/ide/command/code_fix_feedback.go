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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/types"
)

type codeFixFeedback struct {
	command types.CommandData
}

func (cmd *codeFixFeedback) Command() types.CommandData {
	return cmd.command
}

func (cmd *codeFixFeedback) Execute(_ context.Context) (any, error) {
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
		// This un-awaited goroutine outlives the command's execution.
		// It cannot reuse the command's context, as the command executor will cancel it when the command finishes.
		bgCtx := context.Background()
		c := config.CurrentConfig()
		c.Logger().Info().Str("fixId", fixId).Str("feedback", feedback).Msg("Submitting autofix feedback")

		// Get folder from the persistent AiFixHandler using the fix results
		folder, err := cmd.getFolderFromFixId(c, fixId)
		if err != nil {
			c.Logger().Warn().Err(err).Str("fixId", fixId).Msg("Failed to determine folder for feedback, using default org")
			folder = ""
		}

		host, err := code.GetCodeApiUrlForFolder(c, folder)
		if err != nil {
			c.Logger().Error().Str("fixId", fixId).Str("host", host).Str("folder", string(folder)).Err(err).Msg("Failed to get endpoint from host")
		}

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
			Host:                host,
			CodeRequestContext:  code.NewAutofixCodeRequestContext(folder),
			IdeExtensionDetails: code.GetAutofixIdeExtensionDetails(c),
		}

		err = deepCodeLLMBinding.SubmitAutofixFeedback(bgCtx, fixId, options)
		if err != nil {
			c.Logger().Err(err).Str("fixId", fixId).Str("feedback", feedback).Msg("failed to submit autofix feedback")
		}
	}()

	return nil, nil
}

// getFolderFromFixId retrieves the folder path by looking up the fix results from the persistent HtmlRenderer.
// The HtmlRenderer is a singleton that persists across the application lifecycle,
// so the AiFixHandler maintains the fix results even after the original command completes.
func (cmd *codeFixFeedback) getFolderFromFixId(c *config.Config, fixId string) (types.FilePath, error) {
	// Get the persistent HtmlRenderer which contains the AiFixHandler with stored fix results
	// Pass nil for FF service since we're only reading from existing state, not creating a new renderer
	htmlRenderer, err := code.GetHTMLRenderer(c, nil)
	if err != nil {
		return "", fmt.Errorf("HTML renderer not initialized: %w", err)
	}

	// Get the file path from the fix results stored in the AiFixHandler
	filePath, _, err := htmlRenderer.AiFixHandler.GetResults(fixId)
	if err != nil {
		return "", fmt.Errorf("fix results not found: %w", err)
	}

	if filePath == "" {
		return "", fmt.Errorf("fix results contain empty file path")
	}

	// Determine which workspace folder contains this file
	ws := c.Workspace()
	if ws == nil {
		return "", fmt.Errorf("no workspace configured")
	}

	folder := ws.GetFolderContaining(types.FilePath(filePath))
	if folder == nil {
		return "", fmt.Errorf("file %s not in any workspace folder", filePath)
	}

	folderPath := folder.Path()
	c.Logger().Debug().Str("fixId", fixId).Str("filePath", filePath).Str("folder", string(folderPath)).Msg("Determined folder from fix results")
	return folderPath, nil
}

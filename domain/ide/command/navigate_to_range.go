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
	"encoding/json"
	"strings"

	"github.com/snyk/code-client-go/llm"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/uri"
)

type navigateToRangeCommand struct {
	command            types.CommandData
	srv                types.Server
	logger             *zerolog.Logger
	deepCodeLLMBinding llm.DeepCodeLLMBinding
	c                  *config.Config
}

func (cmd *navigateToRangeCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *navigateToRangeCommand) Execute(_ context.Context) (any, error) {
	method := "navigateToRangeCommand.Execute"
	if len(cmd.command.Arguments) < 2 {
		cmd.logger.Warn().Str("method", method).Msg("received NavigateToRangeCommand without range")
	}
	// convert to correct type
	var myRange snyk.Range
	args := cmd.command.Arguments
	marshal, err := json.Marshal(args[1])
	if err != nil {
		return nil, errors.Wrap(err, "couldn't marshal range to json")
	}
	err = json.Unmarshal(marshal, &myRange)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't unmarshal range from json")
	}

	path, ok := args[0].(string)
	if !ok {
		return nil, errors.Errorf("invalid range path: %s", args[0])
	}

	var documentUri sglsp.DocumentURI
	if !strings.HasPrefix(path, "snyk://") {
		documentUri = uri.PathToUri(path)
	} else {
		documentUri = sglsp.DocumentURI(path)
		// TODO: move this to a new command to process snyk magnet link
		renderer, rendererErr := code.GetHTMLRenderer(cmd.c, cmd.deepCodeLLMBinding)
		if rendererErr == nil {
			renderer.AiFixHandler.SetAutoTriggerAiFix(true)
		}
	}

	params := types.ShowDocumentParams{
		Uri:       documentUri,
		External:  false,
		TakeFocus: true,
		Selection: converter.ToRange(myRange),
	}

	cmd.logger.Debug().
		Str("method", method).
		Interface("params", params).
		Msg("showing Document")
	rsp, err := cmd.srv.Callback(context.Background(), "window/showDocument", params)
	cmd.logger.Debug().Str("method", method).Interface("callback", rsp).Send()
	return nil, err
}

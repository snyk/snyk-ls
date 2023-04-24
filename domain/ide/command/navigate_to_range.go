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

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/uri"
)

type navigateToRangeCommand struct {
	command snyk.CommandData
	srv     lsp.Server
}

func (cmd *navigateToRangeCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *navigateToRangeCommand) Execute(ctx context.Context) (any, error) {
	method := "navigateToRangeCommand.Execute"
	if len(cmd.command.Arguments) < 2 {
		log.Warn().Str("method", method).Msg("received NavigateToRangeCommand without range")
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

	params := lsp.ShowDocumentParams{
		Uri:       uri.PathToUri(args[0].(string)),
		External:  false,
		TakeFocus: true,
		Selection: converter.ToRange(myRange),
	}

	log.Info().
		Str("method", method).
		Interface("params", params).
		Msg("showing Document")
	rsp, err := cmd.srv.Callback(context.Background(), "window/showDocument", params)
	log.Debug().Str("method", method).Interface("callback", rsp).Send()
	return nil, err
}

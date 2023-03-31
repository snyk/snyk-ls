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
	"fmt"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/pkg/auth"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/server"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/uri"
)

func CreateFromCommandData(commandData snyk.CommandData, srv server.Server) (snyk.Command, error) {
	switch commandData.CommandId {
	case snyk.NavigateToRangeCommand:
		return &navigateToRangeCommand{command: commandData, srv: srv}, nil
	case snyk.WorkspaceScanCommand:
		return &workspaceScanCommand{command: commandData, srv: srv}, nil
	case snyk.WorkspaceFolderScanCommand:
	case snyk.OpenBrowserCommand:
		return &openBrowserCommand{command: commandData}, nil
	case snyk.LoginCommand:
	case snyk.CopyAuthLinkCommand:
	case snyk.LogoutCommand:
	case snyk.TrustWorkspaceFoldersCommand:
	}
	return nil, fmt.Errorf("unknown command %v", commandData)
}

type navigateToRangeCommand struct {
	command snyk.CommandData
	srv     server.Server
}

func (cmd *navigateToRangeCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *navigateToRangeCommand) Execute(_ context.Context) error {
	method := "navigateToRangeCommand.Execute"
	if len(cmd.command.Arguments) < 2 {
		log.Warn().Str("method", method).Msg("received NavigateToRangeCommand without range")
	}
	// convert to correct type
	var myRange snyk.Range
	args := cmd.command.Arguments
	marshal, err := json.Marshal(args[1])
	if err != nil {
		return errors.Wrap(err, "couldn't marshal range to json")
	}
	err = json.Unmarshal(marshal, &myRange)
	if err != nil {
		return errors.Wrap(err, "couldn't unmarshal range from json")
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
	return err
}

type workspaceScanCommand struct {
	command snyk.CommandData
	srv     server.Server
}

func (cmd *workspaceScanCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *workspaceScanCommand) Execute(ctx context.Context) error {
	w := workspace.Get()
	w.ClearIssues(ctx)
	w.ScanWorkspace(ctx)
	HandleUntrustedFolders(ctx, cmd.srv)
	return nil
}

type openBrowserCommand struct {
	command snyk.CommandData
}

func (cmd *openBrowserCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *openBrowserCommand) Execute(_ context.Context) error {
	auth.OpenBrowser(cmd.command.Arguments[0].(string))
	return nil
}

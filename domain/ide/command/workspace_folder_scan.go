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

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/internal/types"
)

type workspaceFolderScanCommand struct {
	command types.CommandData
	srv     types.Server
	logger  *zerolog.Logger
}

func (cmd *workspaceFolderScanCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *workspaceFolderScanCommand) Execute(ctx context.Context) (any, error) {
	method := "workspaceFolderScanCommand.Execute"
	args := cmd.Command().Arguments
	w := workspace.Get()
	if len(args) != 1 {
		err := errors.New("received WorkspaceFolderScanCommand without path")
		cmd.logger.Warn().Str("method", method).Err(err).Send()
		return nil, err
	}
	path := args[0].(string)
	f := w.GetFolderContaining(path)
	if f == nil {
		err := errors.New("received WorkspaceFolderScanCommand with path not in workspace")
		cmd.logger.Warn().Str("method", method).Err(err).Send()
		cmd.logger.Warn().Interface("folders", w.Folders())
		return nil, err
	}
	f.Clear()
	f.ScanFolder(ctx)
	HandleUntrustedFolders(ctx, cmd.srv)
	return nil, nil
}

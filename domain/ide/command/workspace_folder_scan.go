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

	"github.com/pkg/errors"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type workspaceFolderScanCommand struct {
	command types.CommandData
	srv     types.Server
	c       *config.Config
}

func (cmd *workspaceFolderScanCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *workspaceFolderScanCommand) Execute(ctx context.Context) (any, error) {
	method := "workspaceFolderScanCommand.Execute"
	args := cmd.Command().Arguments
	w := cmd.c.Workspace()
	if len(args) != 1 {
		err := errors.New("received WorkspaceFolderScanCommand without path")
		cmd.c.Logger().Warn().Str("method", method).Err(err).Send()
		return nil, err
	}
	path, ok := args[0].(string)
	filePath := types.FilePath(path)
	if !ok {
		return nil, fmt.Errorf("received WorkspaceFolderScanCommand with invalid path")
	}
	f := w.GetFolderContaining(filePath)
	if f == nil {
		err := errors.New("received WorkspaceFolderScanCommand with path not in workspace")
		cmd.c.Logger().Warn().Str("method", method).Err(err).Send()
		cmd.c.Logger().Warn().Interface("folders", w.Folders())
		return nil, err
	}
	f.Clear()
	f.ScanFolder(ctx)
	HandleUntrustedFolders(ctx, cmd.c, cmd.srv)
	return nil, nil
}

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

	"github.com/snyk/snyk-ls/domain/ide/server"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
)

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

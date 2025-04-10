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

	"github.com/snyk/snyk-ls/application/config"
	context2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/types"
)

type workspaceScanCommand struct {
	command types.CommandData
	srv     types.Server
	c       *config.Config
}

func (cmd *workspaceScanCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *workspaceScanCommand) Execute(ctx context.Context) (any, error) {
	w := cmd.c.Workspace()
	w.Clear()
	args := cmd.command.Arguments
	enrichedCtx := cmd.enrichContextWithScanSource(ctx, args)
	w.ScanWorkspace(enrichedCtx)
	HandleUntrustedFolders(enrichedCtx, cmd.c, cmd.srv)
	return nil, nil
}

func (cmd *workspaceScanCommand) enrichContextWithScanSource(ctx context.Context, args []any) context.Context {
	if len(args) == 0 {
		return ctx
	}

	sc, ok := args[0].(string)
	if !ok {
		return ctx
	}

	if sc != context2.IDE.String() && sc != context2.LLM.String() {
		return ctx
	}

	scanSource := context2.ScanSource(sc)
	return context2.NewContextWithScanSource(ctx, scanSource)
}

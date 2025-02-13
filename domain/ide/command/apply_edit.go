/*
 * © 2025 Snyk Limited
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
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
	"time"
)

type applyEditCommand struct {
	command  types.CommandData
	notifier notification.Notifier
	logger   *zerolog.Logger
}

func (cmd *applyEditCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *applyEditCommand) Execute(_ context.Context) (any, error) {
	args, ok := cmd.command.Arguments[0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid edit")
	}
	cmd.logger.Debug().Str("method", "applyEditCommand.Execute").Msgf("applying edit %s", args)

	//edit := FigureOutHowToGetAnEditHere()

	cmd.notifier.Send(types.ApplyWorkspaceEditParams{
		Label: "Snyk Code fix",
		Edit:  converter.ToWorkspaceEdit(edit),
	})

	// reset codelenses
	//issues[i].CodelensCommands = nil

	// Give client some time to apply edit, then refresh code lenses to hide stale codelens for the fixed issue
	time.Sleep(1 * time.Second)
	cmd.notifier.Send(types.CodeLensRefresh{})
	return nil, nil
}

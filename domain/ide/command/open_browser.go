/*
 * © 2022 Snyk Limited All rights reserved.
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

	"github.com/snyk/go-application-framework/pkg/auth"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type OpenBrowserCommand struct {
	command snyk.Command
}

func NewOpenBrowserCommand(url string) *OpenBrowserCommand {
	return &OpenBrowserCommand{
		command: snyk.Command{
			Title:     snyk.OpenBrowserCommand,
			CommandId: snyk.OpenBrowserCommand,
			Arguments: []any{url},
		},
	}
}

func (cmd *OpenBrowserCommand) Command() snyk.Command {
	return cmd.command
}

func (cmd *OpenBrowserCommand) Execute(_ context.Context) error {
	auth.OpenBrowser(cmd.command.Arguments[0].(string))
	return nil
}

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

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/snyk-ls/internal/types"
)

type openBrowserCommand struct {
	command types.CommandData
	logger  *zerolog.Logger
}

func (cmd *openBrowserCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *openBrowserCommand) Execute(ctx context.Context) (any, error) {
	url := cmd.command.Arguments[0].(string)
	cmd.logger.Debug().Str("method", "openBrowserCommand.Execute").Msgf("opening browser url %s", url)
	auth.OpenBrowser(url)
	return nil, nil
}

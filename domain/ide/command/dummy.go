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
	"os/exec"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type dummyCommand struct {
	command snyk.CommandData
}

func (cmd *dummyCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *dummyCommand) Execute(_ context.Context) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "dummyCommand.Execute").Logger()

	cmdStruct := exec.Command("cmd", "-C", "dir")
	out, err := cmdStruct.Output()
	if err == nil {
		logger.Warn().Str("lsoutput", string(out)).Msg("Output from dummyCommand")
	}

	return nil, nil
}

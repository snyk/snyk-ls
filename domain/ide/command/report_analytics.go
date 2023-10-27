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

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
)

type reportAnalyticsCommand struct {
	command snyk.CommandData
}

func (cmd *reportAnalyticsCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *reportAnalyticsCommand) Execute(_ context.Context) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "reportAnalyticsCommand.Execute").Logger()

	for _, arg := range cmd.command.Arguments {
		payload, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("error converting argument to string. %v", arg)
		}
		err := analytics.SendAnalyticsToAPI(c, []byte(payload))
		if err != nil {
			logger.Err(err).Msg("error sending analytics to API")
			return nil, err
		}
	}
	return nil, nil
}

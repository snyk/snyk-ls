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
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/internal/types"
)

type reportAnalyticsCommand struct {
	command               types.CommandData
	authenticationService authentication.AuthenticationService
}

func (cmd *reportAnalyticsCommand) Command() types.CommandData {
	return cmd.command
}

func (cmd *reportAnalyticsCommand) Execute(_ context.Context) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "reportAnalyticsCommand.Execute").Logger()

	isAuthenticated := cmd.authenticationService.IsAuthenticated()

	if !isAuthenticated {
		logger.Info().Msg("not authenticated, skipping analytics reporting")
		return nil, nil
	}

	for _, arg := range cmd.command.Arguments {
		payload, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("error converting argument to string. %v", arg)
		}

		// Send to first folder's org since analytics are sent to a specific org,
		// the first folder's org has as good a chance as any to work and not 404.
		// Pre-built payloads don't have folder context and are not folder-specific.
		// TODO - This is a temporary solution to avoid inflating analytics counts.
		ws := c.Workspace()
		if ws != nil {
			folders := ws.Folders()
			if len(folders) > 0 {
				firstFolderOrg := c.FolderOrganization(folders[0].Path())
				err := analytics.SendAnalyticsToAPI(c.Engine(), c.DeviceID(), firstFolderOrg, []byte(payload))
				if err != nil {
					logger.Err(err).Str("firstFolderOrg", firstFolderOrg).Msg("error sending analytics to API")
					return nil, err
				}
				continue
			}
		}

		// Fallback: If no folders, send with empty org to use the user's preferred org from the web UI
		err := analytics.SendAnalyticsToAPI(c.Engine(), c.DeviceID(), "", []byte(payload))
		if err != nil {
			logger.Err(err).Msg("error sending analytics to API")
			return nil, err
		}
	}
	return nil, nil
}

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

	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/types"
)

type sastEnabled struct {
	command               types.CommandData
	apiClient             snyk_api.SnykApiClient
	logger                *zerolog.Logger
	authenticationService authentication.AuthenticationService
}

func (cmd *sastEnabled) Command() types.CommandData {
	return cmd.command
}

func (cmd *sastEnabled) Execute(_ context.Context) (any, error) {
	isAuthenticated := cmd.authenticationService.IsAuthenticated()

	if !isAuthenticated {
		cmd.logger.Info().Str("method", "sastEnabled.Execute").Msg("not authenticated, skipping sast check")
		return nil, nil
	}

	sastResponse, err := cmd.apiClient.SastSettings()
	return sastResponse, err
}

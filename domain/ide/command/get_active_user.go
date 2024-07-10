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
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

// oauthRefreshCommand is a command that refreshes the authentication token
// This is needed because the token is only valid for a certain period of time
// For doing this we call the whoami workflow that will refresh the token automatically
type getActiveUser struct {
	command               types.CommandData
	authenticationService authentication.AuthenticationService
	notifier              noti.Notifier
}

func (cmd *getActiveUser) Command() types.CommandData {
	return cmd.command
}

func (cmd *getActiveUser) Execute(_ context.Context) (any, error) {
	logger := config.CurrentConfig().Logger().With().Str("method", "getActiveUser.Execute").Logger()
	isAuthenticated, err := cmd.authenticationService.IsAuthenticated()
	if err != nil {
		logger.Warn().Err(err).Msg("error checking auth status")
	}

	if !isAuthenticated {
		logger.Info().Msg("not authenticated, skipping user retrieval")
		return nil, nil
	}

	user, err := authentication.GetActiveUser()
	return user, err
}

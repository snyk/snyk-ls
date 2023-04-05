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

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/util"
)

type oauthRefreshCommand struct {
	command     snyk.CommandData
	authService snyk.AuthenticationService
}

func (cmd *oauthRefreshCommand) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *oauthRefreshCommand) Execute(_ context.Context) error {
	c := config.CurrentConfig()
	if c.AuthenticationMethod() != lsp.OAuthAuthentication {
		log.Debug().Str("method", "oauthRefreshCommand.Execute").Msg("authentication method is token, no refresh needed")
		return nil
	}

	oldToken := c.Token()
	conf := c.Engine().GetConfiguration()
	conf.Set("experimental", true)

	log.Debug().Str("method", "oauthRefreshCommand.Execute").Msgf("calling whoami workflow")
	_, err := c.Engine().Invoke(localworkflows.WORKFLOWID_WHOAMI)
	if err != nil {
		return errors.Wrap(err, "failed to invoke whoami workflow")
	}
	var token string
	if c.AuthenticationMethod() == lsp.OAuthAuthentication {
		token = conf.GetString(auth.CONFIG_KEY_OAUTH_TOKEN)
	} else {
		token = conf.GetString(configuration.AUTHENTICATION_TOKEN)
	}

	if oldToken != token {
		log.Debug().Str("method", "oauthRefreshCommand.Execute").
			Str("hashed token", util.Hash([]byte(token))[0:16]).
			Msgf("refresh successful, received token")

		cmd.authService.UpdateCredentials(token, true)

		log.Debug().Str("method", "oauthRefreshCommand.Execute").
			Str("hashed token", util.Hash([]byte(token))[0:16]).
			Msgf("updated credentials")

	}
	return nil
}

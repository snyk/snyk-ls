/*
 * © 2023-2024 Snyk Limited
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
	"strings"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

var instance types.CommandService

type serviceImpl struct {
	authService   authentication.AuthenticationService
	notifier      noti.Notifier
	learnService  learn.Service
	issueProvider snyk.IssueProvider
	codeApiClient SnykCodeHttpClient
	codeScanner   *code.Scanner
	cli           cli.Executor
}

func NewService(authService authentication.AuthenticationService, notifier noti.Notifier, learnService learn.Service, issueProvider snyk.IssueProvider, codeApiClient SnykCodeHttpClient, codeScanner *code.Scanner, cli cli.Executor) types.CommandService {
	return &serviceImpl{
		authService:   authService,
		notifier:      notifier,
		learnService:  learnService,
		issueProvider: issueProvider,
		codeApiClient: codeApiClient,
		codeScanner:   codeScanner,
		cli:           cli,
	}
}

// SetService sets the singleton instance of the command service.
func SetService(service types.CommandService) {
	instance = service
}

// Service returns the singleton instance of the command service. If not already created,
// it will create a new instance.
func Service() types.CommandService {
	return instance
}

func (s *serviceImpl) ExecuteCommandData(ctx context.Context, commandData types.CommandData, server types.Server) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "command.serviceImpl.ExecuteCommandData").Logger()
	if c.Offline() {
		logger.Warn().Msgf("we are offline, not executing %s", commandData.CommandId)
		return nil, nil
	}

	logger.Debug().Msgf("executing command %s", commandData.CommandId)

	command, err := CreateFromCommandData(c, commandData, server, s.authService, s.learnService, s.notifier, s.issueProvider, s.codeApiClient, s.codeScanner, s.cli)
	if err != nil {
		logger.Err(err).Msg("failed to create command")
		return nil, err
	}

	result, err := command.Execute(ctx)

	if err != nil {
		logger.Err(err).Msg("failed to execute command")
	}

	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		s.notifier.SendShowMessage(sglsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		s.authService.Logout(ctx)
		return nil, nil
	}

	return result, err
}

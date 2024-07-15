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
}

func NewService(
	authService authentication.AuthenticationService,
	notifier noti.Notifier,
	learnService learn.Service,
	issueProvider snyk.IssueProvider,
	codeApiClient SnykCodeHttpClient,
	codeScanner *code.Scanner,
) types.CommandService {
	return &serviceImpl{
		authService:   authService,
		notifier:      notifier,
		learnService:  learnService,
		issueProvider: issueProvider,
		codeApiClient: codeApiClient,
		codeScanner:   codeScanner,
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

func (service *serviceImpl) ExecuteCommandData(ctx context.Context, commandData types.CommandData, server types.Server) (any, error) {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "command.serviceImpl.ExecuteCommandData").Logger()

	logger.Debug().Msgf("executing command %s", commandData.CommandId)

	command, err := CreateFromCommandData(c, commandData, server, service.authService, service.learnService, service.notifier, service.issueProvider, service.codeApiClient, service.codeScanner)
	if err != nil {
		logger.Err(err).Msg("failed to create command")
		return nil, err
	}

	result, err := command.Execute(ctx)

	if err != nil {
		logger.Err(err).Msg("failed to execute command")
	}

	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		service.notifier.SendShowMessage(sglsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		service.authService.Logout(ctx)
		return nil, nil
	}

	return result, err
}

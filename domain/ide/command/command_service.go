/*
 * © 2023 Snyk Limited All rights reserved.
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

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/internal/lsp"
)

var instance snyk.CommandService

type serviceImpl struct {
	authService   snyk.AuthenticationService
	notifier      noti.Notifier
	learnService  learn.Service
	issueProvider ide.IssueProvider
	codeApiClient SnykCodeHttpClient
}

func NewService(authService snyk.AuthenticationService, notifier noti.Notifier, learnService learn.Service, issueProvider ide.IssueProvider, codeApiClient SnykCodeHttpClient) snyk.CommandService {
	return &serviceImpl{
		authService:   authService,
		notifier:      notifier,
		learnService:  learnService,
		issueProvider: issueProvider,
		codeApiClient: codeApiClient,
	}
}

// SetService sets the singleton instance of the command service.
func SetService(service snyk.CommandService) {
	instance = service
}

// Service returns the singleton instance of the command service. If not already created,
// it will create a new instance.
func Service() snyk.CommandService {
	return instance
}

func (service *serviceImpl) ExecuteCommandData(ctx context.Context, commandData snyk.CommandData, server lsp.Server) (any, error) {
	log.Debug().Str(
		"method",
		"command.serviceImpl.ExecuteCommandData",
	).Msgf("executing command %s", commandData.CommandId)

	command, err := CreateFromCommandData(commandData, server, service.authService, service.learnService, service.notifier, service.issueProvider, service.codeApiClient)
	if err != nil {
		log.Error().Err(err).Str("method", "command.serviceImpl.ExecuteCommandData").Msg("failed to create command")
		return nil, err
	}

	result, err := command.Execute(ctx)
	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		service.notifier.SendShowMessage(sglsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		service.authService.Logout(ctx)
		return nil, nil
	}

	return result, err
}

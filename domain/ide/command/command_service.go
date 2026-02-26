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
	"errors"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/types"
)

var instance types.CommandService

type serviceImpl struct {
	authService        authentication.AuthenticationService
	featureFlagService featureflag.Service
	notifier           noti.Notifier
	learnService       learn.Service
	issueProvider      snyk.IssueProvider
	codeScanner        *code.Scanner
	cli                cli.Executor
	ldxSyncService     LdxSyncService
	configResolver     types.ConfigResolverInterface
	baseline           *types.SentConfigBaseline
}

func NewService(authService authentication.AuthenticationService, featureFlagService featureflag.Service, notifier noti.Notifier, learnService learn.Service, issueProvider snyk.IssueProvider, codeScanner *code.Scanner, cli cli.Executor, ldxSyncService LdxSyncService, configResolver types.ConfigResolverInterface, baseline *types.SentConfigBaseline) types.CommandService {
	return &serviceImpl{
		authService:        authService,
		featureFlagService: featureFlagService,
		notifier:           notifier,
		learnService:       learnService,
		issueProvider:      issueProvider,
		codeScanner:        codeScanner,
		cli:                cli,
		ldxSyncService:     ldxSyncService,
		configResolver:     configResolver,
		baseline:           baseline,
	}
}

// SetService sets the singleton instance of the command service.
func SetService(service types.CommandService) {
	instance = service
}

// Service returns the singleton instance of the command service.
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
	command, err := CreateFromCommandData(c, commandData, server, s.authService, s.featureFlagService, s.learnService, s.notifier, s.issueProvider, s.codeScanner, s.cli, s.ldxSyncService, s.configResolver, s.baseline)
	if err != nil {
		logger.Err(err).Msg("failed to create command")
		return nil, err
	}

	result, err := command.Execute(ctx)
	if err != nil {
		var snykErr snyk_errors.Error
		if errors.As(err, &snykErr) {
			logger.Err(err).Str("detail", snykErr.Detail).Msg("failed to execute command")
		} else {
			logger.Err(err).Msg("failed to execute command")
		}
	}

	if err != nil && strings.Contains(err.Error(), "400 Bad Request") {
		s.notifier.SendShowMessage(sglsp.MTWarning, "Logging out automatically, available credentials are invalid. Please re-authenticate.")
		s.authService.Logout(ctx)
		return nil, nil
	}

	return result, err
}

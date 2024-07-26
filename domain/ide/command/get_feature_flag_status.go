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
	"errors"
	"fmt"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/types"
)

type featureFlagStatus struct {
	command               types.CommandData
	apiClient             snyk_api.SnykApiClient
	authenticationService authentication.AuthenticationService
}

func (cmd *featureFlagStatus) Command() types.CommandData {
	return cmd.command
}

func (cmd *featureFlagStatus) Execute(_ context.Context) (any, error) {
	logger := config.CurrentConfig().Logger().With().Str("method", "featureFlagStatus.Execute").Logger()
	isAuthenticated := cmd.authenticationService.IsAuthenticated()

	if !isAuthenticated {
		message := "not authenticated, cannot retrieve feature flags"
		logger.Warn().Msg(message)
		return snyk_api.FFResponse{Ok: false, UserMessage: message}, nil
	}

	args := cmd.command.Arguments
	if len(args) < 1 {
		return nil, errors.New("missing feature flag required argument: feature flag name")
	}

	ffStr, ok := args[0].(string)
	if !ok {
		return nil, errors.New("invalid feature flag name argument")
	}

	ff := snyk_api.FeatureFlagType(ffStr)
	ffResponse, err := cmd.apiClient.FeatureFlagStatus(ff)

	message := fmt.Sprintf("Feature flag status for '%s': %v", ffStr, ffResponse.Ok)
	logger.Debug().Msg(message)

	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get feature flag: " + ffStr)
		return snyk_api.FFResponse{Ok: false, UserMessage: err.Error()}, nil
	}

	return snyk_api.FFResponse{Ok: ffResponse.Ok}, nil
}

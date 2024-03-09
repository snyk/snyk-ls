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
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

type featureFlagStatus struct {
	command   snyk.CommandData
	apiClient snyk_api.SnykApiClient
}

func (cmd *featureFlagStatus) Command() snyk.CommandData {
	return cmd.command
}

func (cmd *featureFlagStatus) Execute(ctx context.Context) (any, error) {
	if config.CurrentConfig().Token() == "" {
		return nil, nil
	}

	args := cmd.command.Arguments
	if len(args) < 1 {
		return nil, nil
	}

	ff := args[0].(snyk_api.FeatureFlagType)
	featureFlagResponse, err := cmd.apiClient.FeatureFlagSettings(ff)
	return featureFlagResponse, err
}

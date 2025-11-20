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

package code

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"

	"github.com/snyk/snyk-ls/application/config"
)

func isLocalEngineEnabled(sastResponse *sast_contract.SastResponse) bool {
	return sastResponse != nil && sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled
}

func updateCodeApiLocalEngine(c *config.Config, sastResponse *sast_contract.SastResponse) string {
	if !isLocalEngineEnabled(sastResponse) {
		return ""
	}

	logger := c.Logger().With().Str("method", "updateCodeApiLocalEngine").Logger()
	gafConfig := c.Engine().GetConfiguration()
	url, err := c.GetCodeApiUrlFromCustomEndpoint(sastResponse)
	if err != nil {
		logger.Err(err).Msg("failed to get code api url")
		return ""
	}
	additionalURLs := gafConfig.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, url)
	gafConfig.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
	logger.Debug().Str("snykCodeApi", url).Msg("updated Snyk Code API Local Engine")
	return url
}

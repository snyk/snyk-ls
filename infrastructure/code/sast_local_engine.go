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
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
)

const localEngineMisConfiguredMsg = "Local engine is enabled but URL is not configured."

func (sc *Scanner) isLocalEngineEnabled(sastResponse snyk_api.SastResponse) bool {
	log.Debug().Any("sastResponse", sastResponse).Msg("sast response")
	return sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled
}

func (sc *Scanner) updateCodeApiLocalEngine(sastResponse snyk_api.SastResponse) bool {
	method := "updateCodeApiLocalEngine"

	if sc.isLocalEngineEnabled(sastResponse) && len(sastResponse.LocalCodeEngine.Url) > 1 {
		config.CurrentConfig().SetSnykCodeApi(sastResponse.LocalCodeEngine.Url)
		api := config.CurrentConfig().SnykCodeApi()
		log.Debug().Str("snykCodeApi", api).Msg("updated Snyk Code API Local Engine")
		return true
	}
	sc.notifier.SendShowMessage(
		sglsp.MessageType(sglsp.Error),
		localEngineMisConfiguredMsg,
	)
	log.Error().Str("method", method).Msg(localEngineMisConfiguredMsg)
	return false

}

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
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/data_structure"
)

const localEngineMisConfiguredActionItemTitle snyk.MessageAction = "SCLE Docs"
const closeLocalEngineMisConfiguredActionItemTitle snyk.MessageAction = "Close"
const localEngineMisConfiguredMsg = "Snyk Code Local Engine (SCLE) is enabled but the SCLE URL is not configured. Read our docs on how you can configure the SCLE URL"
const localEngineDocsURL = "https://docs.snyk.io/products/snyk-code/deployment-options/snyk-code-local-engine/cli-and-ide"

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

	actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.Command]()
	commandData := snyk.CommandData{
		Title:     snyk.OpenBrowserCommand,
		CommandId: snyk.OpenBrowserCommand,
		Arguments: []any{localEngineDocsURL},
	}
	cmd, err := command.CreateFromCommandData(commandData, nil, nil, sc.learnService, sc.notifier, nil, nil)
	if err != nil {
		message := "couldn't create open browser command"
		log.Err(err).Str("method", method).Msg(message)
		sc.errorReporter.CaptureError(errors.Wrap(err, message))
	} else {
		actionCommandMap.Add(localEngineMisConfiguredActionItemTitle, cmd)
	}
	actionCommandMap.Add(closeLocalEngineMisConfiguredActionItemTitle, nil)

	sc.notifier.Send(snyk.ShowMessageRequest{
		Message: localEngineMisConfiguredMsg,
		Type:    snyk.Error,
		Actions: actionCommandMap,
	})
	log.Error().Str("method", method).Msg(localEngineMisConfiguredMsg)
	return false
}

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
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/data_structure"
)

const codeDisabledInOrganisationMessageText = "It looks like your organization has disabled Snyk Code. " +
	"You can easily enable it by clicking on 'Enable Snyk Code'. " +
	"This will open your organization settings in your browser."

const enableSnykCodeMessageActionItemTitle snyk.MessageAction = "Enable Snyk Code"
const closeMessageActionItemTitle snyk.MessageAction = "Close"
const localCodeEngineWarning = "Snyk Code is configured to use a Local Code Engine instance. This setup is not yet supported."

func (sc *Scanner) isSastEnabled() bool {
	sastResponse, err := sc.SnykApiClient.SastSettings()
	method := "isSastEnabled"
	if err != nil {
		log.Error().Err(err).Str("method", method).Msg("couldn't get sast enablement")
		sc.errorReporter.CaptureError(err)
		return false
	}

	if !sastResponse.SastEnabled {
		// this is processed in the listener registered to translate into the right client protocol
		actionCommandMap := data_structure.NewOrderedMap[snyk.MessageAction, snyk.Command]()
		commandData := snyk.CommandData{
			Title:     snyk.OpenBrowserCommand,
			CommandId: snyk.OpenBrowserCommand,
			Arguments: []any{getCodeEnablementUrl()},
		}
		cmd, err := command.CreateFromCommandData(commandData, nil, nil, sc.learnService, sc.notifier, nil, nil)
		if err != nil {
			message := "couldn't create open browser command"
			log.Err(err).Str("method", method).Msg(message)
			sc.errorReporter.CaptureError(errors.Wrap(err, message))
		} else {
			actionCommandMap.Add(enableSnykCodeMessageActionItemTitle, cmd)
		}
		actionCommandMap.Add(closeMessageActionItemTitle, nil)

		sc.notifier.Send(snyk.ShowMessageRequest{
			Message: codeDisabledInOrganisationMessageText,
			Type:    snyk.Warning,
			Actions: actionCommandMap,
		})
		return false
	}

	if sastResponse.LocalCodeEngine.Enabled {
		sc.notifier.SendShowMessage(
			sglsp.Warning,
			localCodeEngineWarning,
		)
		return false
	}

	getCodeSettings().SetAutofixEnabled(sastResponse.AutofixEnabled)

	return true
}

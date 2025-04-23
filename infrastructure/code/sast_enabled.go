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
	"github.com/snyk/snyk-ls/internal/data_structure"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
)

const codeDisabledInOrganisationMessageText = "It looks like your organization has disabled Snyk Code. " +
	"You can easily enable it by clicking on 'Enable Snyk Code'. " +
	"This will open your organization settings in your browser."

const enableSnykCodeMessageActionItemTitle types.MessageAction = "Enable Snyk Code"
const closeMessageActionItemTitle types.MessageAction = "Close"

func (sc *Scanner) isSastEnabled(sastResponse *sast_contract.SastResponse) bool {
	if !sastResponse.SastEnabled {
		// this is processed in the listener registered to translate into the right client protocol
		actionCommandMap := data_structure.NewOrderedMap[types.MessageAction, types.CommandData]()
		commandData := types.CommandData{
			Title:     types.OpenBrowserCommand,
			CommandId: types.OpenBrowserCommand,
			Arguments: []any{getCodeEnablementUrl()},
		}

		actionCommandMap.Add(enableSnykCodeMessageActionItemTitle, commandData)
		actionCommandMap.Add(closeMessageActionItemTitle, types.CommandData{})

		sc.notifier.Send(types.ShowMessageRequest{
			Message: codeDisabledInOrganisationMessageText,
			Type:    types.Warning,
			Actions: actionCommandMap,
		})
		return false
	}

	getCodeSettings().SetAutofixEnabled(sastResponse.AutofixEnabled)

	return true
}

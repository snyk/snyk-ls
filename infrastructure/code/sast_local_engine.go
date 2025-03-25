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
	"github.com/snyk/snyk-ls/application/config"
)

func (sc *Scanner) isLocalEngineEnabled(sastResponse configuration.SastResponse) bool {
	sc.C.Logger().Debug().Any("sastResponse", sastResponse).Msg("sast response")
	return sastResponse.SastEnabled && sastResponse.LocalCodeEngine.Enabled
}

func (sc *Scanner) updateCodeApiLocalEngine(sastResponse configuration.SastResponse) {
	config.CurrentConfig().SetSnykCodeApi(sastResponse.LocalCodeEngine.Url)
	api := config.CurrentConfig().SnykCodeApi()
	sc.C.Logger().Debug().Str("snykCodeApi", api).Msg("updated Snyk Code API Local Engine")
}

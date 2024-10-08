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
package code

import (
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

const (
	// Autofix is disabled by default
	defaultAutofixEnabled = false
)

var (
	codeSettingsSingleton      *codeSettings
	codeSettingsSingletonMutex = &sync.Mutex{}
)

type codeSettings struct {
	isAutofixEnabled concurrency.AtomicBool
}

// Create new code settings
func newCodeSettings() *codeSettings {
	s := &codeSettings{}
	s.isAutofixEnabled.Set(defaultAutofixEnabled)
	return s
}

// Gets the codeSettings singleton, lazily constructing it on the fly at the first call
func getCodeSettings() *codeSettings {
	if codeSettingsSingleton == nil {
		resetCodeSettings()
	}
	return codeSettingsSingleton
}

// Separated out from `getCodeSettings()` for using in tests with `t.Cleanup(resetCodeSettings)`
func resetCodeSettings() {
	codeSettingsSingletonMutex.Lock()
	defer codeSettingsSingletonMutex.Unlock()
	codeSettingsSingleton = newCodeSettings()
}

func (cs *codeSettings) SetAutofixEnabled(enabled bool) {
	codeSettingsSingletonMutex.Lock()
	defer codeSettingsSingletonMutex.Unlock()

	cs.isAutofixEnabled.Set(enabled)
}

func getCodeEnablementUrl() string {
	c := config.CurrentConfig()
	integrationName := c.IntegrationName()
	return c.SnykUI() + "/manage/snyk-code?from=" + integrationName
}

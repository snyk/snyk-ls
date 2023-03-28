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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/concurrency"
)

const (
	// String "true" or "false", see `defaultAutofixEnabled`
	autofixEnabledEnvVarKey = "SNYK_AUTOFIX_ENABLED"
	// By default this is disabled
	defaultAutofixEnabled = false
)

var (
	codeSettingsSingleton      *codeSettings
	codeSettingsSingletonMutex = &sync.Mutex{}
)

type codeSettings struct {
	isAutofixEnabled concurrency.AtomicBool
	// Files of this type shall have code actions enabled on them, see `GetFilters`
	autofixExtensions *concurrency.AtomicMap
}

// Create new code settings
func newCodeSettings() *codeSettings {
	s := &codeSettings{}
	s.isAutofixEnabled.Set(getAutofixEnabledFromEnvOrDefault())
	s.autofixExtensions = nil
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

// Attempts to read the `autofixEnabledEnvVarKey` env variable or sets the
// bool to default
func getAutofixEnabledFromEnvOrDefault() bool {
	env := os.Getenv(autofixEnabledEnvVarKey)
	if env == "" {
		return defaultAutofixEnabled
	}

	parseBool, err := strconv.ParseBool(env)
	if err != nil {
		return defaultAutofixEnabled
	}
	return parseBool
}

// Does nothing if the extensions are already set
func (cs *codeSettings) setAutofixExtensionsIfNotSet(autofixExtensions []string) {
	codeSettingsSingletonMutex.Lock()
	defer codeSettingsSingletonMutex.Unlock()

	if cs.autofixExtensions != nil {
		return
	}

	cs.autofixExtensions = &concurrency.AtomicMap{}
	for _, ext := range autofixExtensions {
		cs.autofixExtensions.Put(ext, true)
	}
}

func getCodeEnablementUrl() string {
	api := config.CurrentConfig().SnykApi()
	apiUrl, err := url.Parse(api)
	if err != nil {
		return "default api url"
	}

	apiUrl.Path = "/"

	// if multi tenant, add `app.` subdomain
	if !isSingleTenant(apiUrl) {
		apiUrl.Host = "app." + apiUrl.Host
	}

	integrationName := config.CurrentConfig().IntegrationName()
	return apiUrl.String() + "manage/snyk-code?from=" + integrationName
}

func isSingleTenant(url *url.URL) bool {
	return strings.HasPrefix(url.Host, "app") && strings.HasSuffix(url.Host, "snyk.io")
}

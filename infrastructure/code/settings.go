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
	"strings"

	"github.com/snyk/snyk-ls/application/config"
)

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

	return apiUrl.String() + "manage/snyk-code?from=VS_CODE"
}

func isSingleTenant(url *url.URL) bool {
	return strings.HasPrefix(url.Host, "app") && strings.HasSuffix(url.Host, "snyk.io")
}

/*
 * © 2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

// MigrateSettingsToLocalFields converts an old Settings struct to a map of
// canonical config name → LocalConfigField. It uses the config.ideKey annotation
// on registered flags to map Settings JSON field names to canonical names.
// Fields that are empty/zero are excluded (Changed: false semantics).
func MigrateSettingsToLocalFields(settings *Settings, fs *pflag.FlagSet) map[string]*configuration.LocalConfigField {
	if settings == nil {
		return nil
	}

	result := make(map[string]*configuration.LocalConfigField)

	ideKeyToCanonical := buildIdeKeyMapping(fs)
	settingsMap := settingsToMap(settings)

	for ideKey, value := range settingsMap {
		canonicalName, ok := ideKeyToCanonical[ideKey]
		if !ok {
			continue
		}
		if isSettingValueEmpty(value) {
			continue
		}
		result[canonicalName] = &configuration.LocalConfigField{
			Value:   value,
			Changed: true,
		}
	}

	return result
}

func buildIdeKeyMapping(fs *pflag.FlagSet) map[string]string {
	result := make(map[string]string)
	fs.VisitAll(func(f *pflag.Flag) {
		ideVals, ok := f.Annotations[configuration.AnnotationIdeKey]
		if !ok || len(ideVals) == 0 {
			return
		}
		result[ideVals[0]] = f.Name
	})
	return result
}

func settingsToMap(s *Settings) map[string]any {
	m := make(map[string]any)
	add := func(ideKey string, cond bool, val any) {
		if cond {
			m[ideKey] = val
		}
	}
	add("endpoint", s.Endpoint != "", s.Endpoint)
	add("snykCodeApi", s.SnykCodeApi != "", s.SnykCodeApi)
	add("authenticationMethod", s.AuthenticationMethod != "", string(s.AuthenticationMethod))
	add("proxyHttp", s.ProxyHttp != "", s.ProxyHttp)
	add("proxyHttps", s.ProxyHttps != "", s.ProxyHttps)
	add("proxyNoProxy", s.ProxyNoProxy != "", s.ProxyNoProxy)
	add("insecure", s.Insecure != "", s.Insecure)
	add("autoConfigureSnykMcpServer", s.AutoConfigureSnykMcpServer != "", s.AutoConfigureSnykMcpServer)
	add("publishSecurityAtInceptionRules", s.PublishSecurityAtInceptionRules != "", s.PublishSecurityAtInceptionRules)
	add("enableTrustedFoldersFeature", s.EnableTrustedFoldersFeature != "", s.EnableTrustedFoldersFeature)
	add("cliBaseDownloadURL", s.CliBaseDownloadURL != "", s.CliBaseDownloadURL)
	add("cliPath", s.CliPath != "", s.CliPath)
	add("manageBinariesAutomatically", s.ManageBinariesAutomatically != "", s.ManageBinariesAutomatically)
	add("cliReleaseChannel", s.CliReleaseChannel != "", s.CliReleaseChannel)
	add("filterSeverity", s.FilterSeverity != nil, s.FilterSeverity)
	add("riskScoreThreshold", s.RiskScoreThreshold != nil, func() any {
		if s.RiskScoreThreshold != nil {
			return *s.RiskScoreThreshold
		}
		return nil
	}())
	add("activateSnykCode", s.ActivateSnykCode != "", s.ActivateSnykCode)
	add("activateSnykOpenSource", s.ActivateSnykOpenSource != "", s.ActivateSnykOpenSource)
	add("activateSnykIac", s.ActivateSnykIac != "", s.ActivateSnykIac)
	add("activateSnykSecrets", s.ActivateSnykSecrets != "", s.ActivateSnykSecrets)
	add("scanningMode", s.ScanningMode != "", s.ScanningMode)
	add("enableDeltaFindings", s.EnableDeltaFindings != "", s.EnableDeltaFindings)
	add("additionalParams", s.AdditionalParams != "", s.AdditionalParams)
	add("additionalEnv", s.AdditionalEnv != "", s.AdditionalEnv)
	return m
}

func isSettingValueEmpty(value any) bool {
	if value == nil {
		return true
	}
	switch v := value.(type) {
	case string:
		return v == ""
	case *SeverityFilter:
		return v == nil
	case int:
		return false
	default:
		return false
	}
}

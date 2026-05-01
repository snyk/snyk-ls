/*
 * © 2022-2026 Snyk Limited
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

package types

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
)

// GetGlobalOrganization returns the effective global organization via GAF's standard
// resolution chain (configuration.ORGANIZATION). GetString triggers /rest/self
// auto-determination if no org is stored; we cache a successful result by storing it
// back so defaultFuncOrganization returns it directly on the next call (via the UUID
// existingValue fast-path) without an additional /rest/self network call.
//
// Doubles as the priming entry point for ConfigResolver.GlobalOrg() (gated on IsSet):
// callers prime viper via this function so hot-path readers like StateSnapshot find
// the cached UUID without firing /rest/self themselves.
func GetGlobalOrganization(conf configuration.Configuration) string {
	org := conf.GetString(configuration.ORGANIZATION)
	if org != "" {
		// Store the resolved org so that defaultFuncOrganization's UUID fast-path
		// returns it directly next time, avoiding /rest/self.
		conf.Set(configuration.ORGANIZATION, org)
	}
	return org
}

// GetGlobalBool reads a setting using a two-phase lookup:
// 1. UserGlobalKey (explicitly set by the user or IDE via UpdateSettings)
// 2. Bare key fallback (flagset default registered in RegisterAllConfigurations)
// This allows flagset defaults to work without being registered as user-set values,
// preserving the config resolver's precedence chain for LDX-Sync remote overrides.
func GetGlobalBool(conf configuration.Configuration, key string) bool {
	if v := conf.Get(configresolver.UserGlobalKey(key)); v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return conf.GetBool(key)
}

// GetGlobalString reads a setting using a two-phase lookup (see GetGlobalBool).
func GetGlobalString(conf configuration.Configuration, key string) string {
	if v := conf.Get(configresolver.UserGlobalKey(key)); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return conf.GetString(key)
}

// GetGlobalInt reads a setting using a two-phase lookup (see GetGlobalBool).
func GetGlobalInt(conf configuration.Configuration, key string) int {
	if v := conf.Get(configresolver.UserGlobalKey(key)); v != nil {
		switch i := v.(type) {
		case int:
			return i
		case int64:
			return int(i)
		}
	}
	return conf.GetInt(key)
}

// GetFilterSeverityFromConfig returns the severity filter from the given configuration.
func GetFilterSeverityFromConfig(conf configuration.Configuration) SeverityFilter {
	return SeverityFilter{
		Critical: GetGlobalBool(conf, SettingSeverityFilterCritical),
		High:     GetGlobalBool(conf, SettingSeverityFilterHigh),
		Medium:   GetGlobalBool(conf, SettingSeverityFilterMedium),
		Low:      GetGlobalBool(conf, SettingSeverityFilterLow),
	}
}

// SetSeverityFilterOnConfig sets the severity filter on the given configuration. Returns true if the filter was modified.
func SetSeverityFilterOnConfig(conf configuration.Configuration, severityFilter *SeverityFilter, logger *zerolog.Logger) bool {
	if severityFilter == nil {
		return false
	}
	current := GetFilterSeverityFromConfig(conf)
	filterModified := current != *severityFilter
	logger.Trace().Str("method", "SetSeverityFilter").Interface("severityFilter", severityFilter).Msg("Setting severity filter")
	conf.Set(configresolver.UserGlobalKey(SettingSeverityFilterCritical), severityFilter.Critical)
	conf.Set(configresolver.UserGlobalKey(SettingSeverityFilterHigh), severityFilter.High)
	conf.Set(configresolver.UserGlobalKey(SettingSeverityFilterMedium), severityFilter.Medium)
	conf.Set(configresolver.UserGlobalKey(SettingSeverityFilterLow), severityFilter.Low)
	return filterModified
}

// GetIssueViewOptionsFromConfig returns the issue view options from the given configuration.
func GetIssueViewOptionsFromConfig(conf configuration.Configuration) IssueViewOptions {
	return IssueViewOptions{
		OpenIssues:    GetGlobalBool(conf, SettingIssueViewOpenIssues),
		IgnoredIssues: GetGlobalBool(conf, SettingIssueViewIgnoredIssues),
	}
}

// SetIssueViewOptionsOnConfig sets the issue view options on the given configuration. Returns true if options were modified.
func SetIssueViewOptionsOnConfig(conf configuration.Configuration, opts *IssueViewOptions, logger *zerolog.Logger) bool {
	if opts == nil {
		return false
	}
	current := GetIssueViewOptionsFromConfig(conf)
	modified := current != *opts
	logger.Trace().Str("method", "SetIssueViewOptions").Interface("issueViewOptions", opts).Msg("Setting issue view options")
	conf.Set(configresolver.UserGlobalKey(SettingIssueViewOpenIssues), opts.OpenIssues)
	conf.Set(configresolver.UserGlobalKey(SettingIssueViewIgnoredIssues), opts.IgnoredIssues)
	return modified
}

// NewDefaultEnvReadyChannel creates a channel for signaling env readiness and
// stores it in conf under SettingDefaultEnvReadyChannel. The caller must
// close the returned channel when the default environment has been prepared.
func NewDefaultEnvReadyChannel(conf configuration.Configuration) chan struct{} {
	ch := make(chan struct{})
	conf.Set(SettingDefaultEnvReadyChannel, ch)
	return ch
}

// IsDefaultEnvReady returns true if the default environment has been prepared.
func IsDefaultEnvReady(conf configuration.Configuration) bool {
	ch, ok := conf.Get(SettingDefaultEnvReadyChannel).(chan struct{})
	if !ok {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// WaitForDefaultEnv blocks until the default environment has been prepared
// or until the provided context is canceled. If no channel is set, it
// returns nil immediately (nothing to wait for).
func WaitForDefaultEnv(ctx context.Context, conf configuration.Configuration) error {
	ch, ok := conf.Get(SettingDefaultEnvReadyChannel).(chan struct{})
	if !ok {
		return nil
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

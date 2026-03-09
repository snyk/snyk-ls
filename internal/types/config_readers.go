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
)

const (
	severityFilterCritical = "severity_filter_critical"
	severityFilterHigh     = "severity_filter_high"
	severityFilterMedium   = "severity_filter_medium"
	severityFilterLow      = "severity_filter_low"
)

// GetGlobalOrganization returns the effective global organization, respecting precedence:
// UserGlobalKey(SettingOrganization) first, then configuration.ORGANIZATION fallback.
func GetGlobalOrganization(conf configuration.Configuration) string {
	if s, ok := conf.Get(configuration.UserGlobalKey(SettingOrganization)).(string); ok && s != "" {
		return s
	}
	return conf.GetString(configuration.ORGANIZATION)
}

// GetFilterSeverityFromConfig returns the severity filter from the given configuration.
func GetFilterSeverityFromConfig(conf configuration.Configuration) SeverityFilter {
	return SeverityFilter{
		Critical: conf.GetBool(configuration.UserGlobalKey(severityFilterCritical)),
		High:     conf.GetBool(configuration.UserGlobalKey(severityFilterHigh)),
		Medium:   conf.GetBool(configuration.UserGlobalKey(severityFilterMedium)),
		Low:      conf.GetBool(configuration.UserGlobalKey(severityFilterLow)),
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
	conf.Set(configuration.UserGlobalKey(severityFilterCritical), severityFilter.Critical)
	conf.Set(configuration.UserGlobalKey(severityFilterHigh), severityFilter.High)
	conf.Set(configuration.UserGlobalKey(severityFilterMedium), severityFilter.Medium)
	conf.Set(configuration.UserGlobalKey(severityFilterLow), severityFilter.Low)
	return filterModified
}

// GetIssueViewOptionsFromConfig returns the issue view options from the given configuration.
func GetIssueViewOptionsFromConfig(conf configuration.Configuration) IssueViewOptions {
	return IssueViewOptions{
		OpenIssues:    conf.GetBool(configuration.UserGlobalKey(SettingIssueViewOpenIssues)),
		IgnoredIssues: conf.GetBool(configuration.UserGlobalKey(SettingIssueViewIgnoredIssues)),
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
	conf.Set(configuration.UserGlobalKey(SettingIssueViewOpenIssues), opts.OpenIssues)
	conf.Set(configuration.UserGlobalKey(SettingIssueViewIgnoredIssues), opts.IgnoredIssues)
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

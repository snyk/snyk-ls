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

// Returns (nil, false) for an unset entry or a wrap with Changed=false so callers fall
// through the resolver chain. Both wrapped and raw writers write here today (CLI bootstrap,
// init metadata, token, and the folder-scope-at-global OOS sites still go raw).
func userGlobalValue(conf configuration.Configuration, key string) (any, bool) {
	v := conf.Get(configresolver.UserGlobalKey(key))
	if v == nil {
		return nil, false
	}
	if lf, ok := v.(*configresolver.LocalConfigField); ok {
		if lf == nil || !lf.Changed {
			return nil, false
		}
		return lf.Value, true
	}
	return v, true
}

// GetGlobalOrganization returns the effective global organization via GAF's standard
// resolution chain (configuration.ORGANIZATION). GetString triggers /rest/self
// auto-determination if no org is stored; we cache a successful result by storing it
// back so defaultFuncOrganization returns it directly on the next call (via the UUID
// existingValue fast-path) without an additional /rest/self network call.
//
// Doubles as the priming entry point for ConfigResolver.GlobalOrg() (gated on IsSet):
// callers in updateCredentials and initializedHandler invoke this to populate viper
// so hot-path readers like StateSnapshot find the cached UUID without firing
// /rest/self themselves.
func GetGlobalOrganization(conf configuration.Configuration) string {
	org := conf.GetString(configuration.ORGANIZATION)
	if org != "" {
		// Store the resolved org so that defaultFuncOrganization's UUID fast-path
		// returns it directly next time, avoiding /rest/self.
		conf.Set(configuration.ORGANIZATION, org)
	}
	return org
}

// settingName is the bare name (e.g. "automatic_download"), not a prefixed key.
// RemoteMachineKey is not persisted, so only the in-memory shape can appear.
func remoteMachineField(conf configuration.Configuration, settingName string) *configresolver.RemoteConfigField {
	v, _ := conf.Get(configresolver.RemoteMachineKey(settingName)).(*configresolver.RemoteConfigField)
	return v
}

// GetGlobalBool reads a setting at the global (no-folder) level, mirroring the precedence chain
// that configresolver.Resolver.resolveMachine implements for machine-scope settings:
//  1. RemoteMachineKey when locked (LDX-Sync admin lock wins)
//  2. UserGlobalKey (explicitly set by the user or IDE via UpdateSettings)
//  3. RemoteMachineKey when unlocked (LDX-Sync default)
//  4. Bare key fallback (flagset default registered in RegisterAllConfigurations)
//
// Folder/org-scoped settings have no value at RemoteMachineKey, so phases 1 and 3 are inert
// for them and the chain reduces to UserGlobalKey → flagset default.
func GetGlobalBool(conf configuration.Configuration, key string) bool {
	remote := remoteMachineField(conf, key)
	if remote != nil && remote.IsLocked {
		if b, ok := remote.Value.(bool); ok {
			return b
		}
	}
	if v, ok := userGlobalValue(conf, key); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	if remote != nil {
		if b, ok := remote.Value.(bool); ok {
			return b
		}
	}
	return conf.GetBool(key)
}

// GetGlobalString reads a setting using the same precedence chain as GetGlobalBool.
func GetGlobalString(conf configuration.Configuration, key string) string {
	remote := remoteMachineField(conf, key)
	if remote != nil && remote.IsLocked {
		if s, ok := remote.Value.(string); ok {
			return s
		}
	}
	if v, ok := userGlobalValue(conf, key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if remote != nil {
		if s, ok := remote.Value.(string); ok {
			return s
		}
	}
	return conf.GetString(key)
}

func GetGlobalSliceFilePath(conf configuration.Configuration, key string) []FilePath {
	v := conf.Get(configresolver.UserGlobalKey(key))
	if lf, ok := v.(*configresolver.LocalConfigField); ok {
		if lf == nil || !lf.Changed {
			return nil
		}
		fp, _ := lf.Value.([]FilePath)
		return fp
	}
	fp, _ := v.([]FilePath)
	return fp
}

// GetGlobalInt reads a setting using the same precedence chain as GetGlobalBool.
func GetGlobalInt(conf configuration.Configuration, key string) int {
	intFrom := func(v any) (int, bool) {
		switch i := v.(type) {
		case int:
			return i, true
		case int64:
			return int(i), true
		}
		return 0, false
	}
	remote := remoteMachineField(conf, key)
	if remote != nil && remote.IsLocked {
		if n, ok := intFrom(remote.Value); ok {
			return n
		}
	}
	if v, ok := userGlobalValue(conf, key); ok {
		if n, ok := intFrom(v); ok {
			return n
		}
	}
	if remote != nil {
		if n, ok := intFrom(remote.Value); ok {
			return n
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

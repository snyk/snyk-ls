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

// userGlobalValue reads UserGlobalKey for the resolver chain (phase 2 of GetGlobalBool).
//
// Returns (nil, false) for an absent key or a *LocalConfigField with Changed=false so
// the caller falls through to phase 3 (remote-unlocked) / phase 4 (flagset default).
//
// The value at this key takes one of two shapes today (see internal/types/config_writers.go):
//   - *LocalConfigField{Changed: true, Value: v}: written by SetGlobalUser for IDE PATCH /
//     user intent. Returns (v, true).
//   - bare value (no wrap): written by SetGlobalSystemDefault, SetGlobalDeferredFolderScope,
//     or SetGlobalRawForRawReader for init metadata, deferred folder-scope settings, and
//     SettingToken (raw reader). Returns (v, true) — presence is enough; the caller's
//     resolver-chain step decides whether to use it.
func userGlobalValue(conf configuration.Configuration, key string) (any, bool) {
	v := conf.Get(configresolver.UserGlobalKey(key))
	if v == nil {
		return nil, false
	}
	// Unset (UnsetGlobalUser) marks the key with GAF's deletion sentinel rather
	// than removing it, so a reset key reads back non-nil. Treat it as absent so
	// the resolver chain falls through to LDX-Sync / flagset default.
	if configuration.IsKeyDeleted(v) {
		return nil, false
	}
	if lf, ok := v.(*configresolver.LocalConfigField); ok {
		if lf == nil || !lf.Changed {
			return nil, false
		}
		return lf.Value, lf.Changed
	}
	return v, true
}

// GetGlobalOrganization returns the effective global organization via GAF's standard
// resolution chain (configuration.ORGANIZATION). GetString triggers /rest/self
// auto-determination if no org is stored (GAF's default-value cache memoizes that
// result, so repeat reads are already network-free).
//
// Doubles as the priming entry point for ConfigResolver.GlobalOrg(), which is gated on
// IsSet. A resolving GetString populates GAF's default-value cache but does NOT mark the
// key as explicitly set, so we store the result back to flip IsSet true. Callers in
// updateCredentials and initializedHandler invoke this so hot-path readers like
// StateSnapshot surface the org via GlobalOrg() without each needing to resolve it.
func GetGlobalOrganization(conf configuration.Configuration) string {
	org := conf.GetString(configuration.ORGANIZATION)
	if org != "" {
		// Mark the resolved org as explicitly set so the IsSet-guarded GlobalOrg() surfaces it.
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

// GetGlobalSliceFilePath reads a slice-of-FilePath setting at the UserGlobalKey.
// It intentionally does NOT call userGlobalValue (and therefore does NOT carry an
// IsKeyDeleted guard) because no slice-typed key is in GlobalResettableSettings today:
// UnsetGlobalUser never writes a deletion tombstone to any key this function reads,
// so IsKeyDeleted can never be true here in practice.
//
// If a slice-typed setting is ever added to GlobalResettableSettings, this function
// MUST be refactored to call userGlobalValue (which carries the IsKeyDeleted guard)
// or add an explicit configuration.IsKeyDeleted(v) check before the type-assertions
// below. Without that guard a deletion tombstone would be type-asserted to nil and
// silently returned as an empty slice rather than falling through to the flagset default.
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
	// intFrom reports (n, true) when v is a known int shape, (0, false) on type-mismatch
	// so the caller falls through to the next resolver phase. The zero never reaches the
	// user — phase 4 (conf.GetInt at the bare key) returns the flagset default if no
	// other phase produced a value.
	intFrom := func(v any) (int, bool) {
		switch i := v.(type) {
		case int:
			return i, true
		case int64:
			return int(i), true
		case float64:
			// JSON-deserialized ints round-trip as float64. Defensive: globals are
			// not persisted today, but framework-default values can arrive this way.
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
	SetGlobalDeferredFolderScope(conf, SettingSeverityFilterCritical, severityFilter.Critical)
	SetGlobalDeferredFolderScope(conf, SettingSeverityFilterHigh, severityFilter.High)
	SetGlobalDeferredFolderScope(conf, SettingSeverityFilterMedium, severityFilter.Medium)
	SetGlobalDeferredFolderScope(conf, SettingSeverityFilterLow, severityFilter.Low)
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
	SetGlobalDeferredFolderScope(conf, SettingIssueViewOpenIssues, opts.OpenIssues)
	SetGlobalDeferredFolderScope(conf, SettingIssueViewIgnoredIssues, opts.IgnoredIssues)
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

// NewLspInitializedChannel creates a channel for signaling LSP initialization
// and stores it in conf under SettingLspInitializedChannel. Call
// SignalLspInitialized(conf) when the initialized handler completes.
func NewLspInitializedChannel(conf configuration.Configuration) {
	ch := make(chan struct{})
	conf.Set(SettingLspInitializedChannel, ch)
}

// SignalLspInitialized closes the channel stored by NewLspInitializedChannel,
// unblocking all goroutines waiting in WaitForLspInitialized.
// Must not be called concurrently; the LSP protocol guarantees a single
// initialized handler fires per session.
func SignalLspInitialized(conf configuration.Configuration) {
	ch, ok := conf.Get(SettingLspInitializedChannel).(chan struct{})
	if !ok {
		return
	}
	select {
	case <-ch: // already closed — no-op
	default:
		close(ch)
	}
}

// WaitForLspInitialized blocks until LSP initialization is complete.
// Returns immediately if the bool flag is already set (backward-compat with
// tests that set SettingIsLspInitialized directly) or if no channel exists.
func WaitForLspInitialized(conf configuration.Configuration) {
	if conf.GetBool(SettingIsLspInitialized) {
		return
	}
	ch, ok := conf.Get(SettingLspInitializedChannel).(chan struct{})
	if !ok {
		return
	}
	<-ch
}

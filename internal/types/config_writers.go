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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
)

// Four explicit setters for UserGlobalKey writes. The lint rule in .golangci.yaml
// forbids direct conf.Set(configresolver.UserGlobalKey(...), ...) outside this file
// so every write declares its intent up front.
//
// Pick by purpose:
//
//   - SetGlobalUser:                  IDE PATCH or user-driven write. Wraps so
//                                     resolver phase 2 (see GetGlobalBool docs)
//                                     distinguishes user intent from a framework
//                                     default at the same key.
//   - SetGlobalSystemDefault:         init metadata or CLI/process bootstrap that
//                                     is not LDX-Sync routable. Phase-2 wrap has
//                                     no effect here, so the raw write is fine.
//   - SetGlobalDeferredFolderScope:   setting is folder-scoped per
//                                     register_configurations.go but historically
//                                     written at user-global. Migration to a
//                                     folder key is tracked separately; this
//                                     helper marks the callsite as known-debt.
//   - SetGlobalRawForRawReader:       reader is not wrap-aware (e.g. SettingToken
//                                     read via raw conf.GetString). Wrapping the
//                                     write would break the read; both sides need
//                                     to migrate together.

// SetGlobalUser writes a user-intent value for an IDE PATCH or programmatic
// user-driven setting. The value is wrapped as *LocalConfigField{Changed: true}
// so the resolver's phase-2 pass (see GetGlobalBool docs for phase numbering)
// recognizes it as explicit user intent and does not fall through to the
// LDX-Sync remote-default at phase 3.
func SetGlobalUser(conf configuration.Configuration, name string, value any) {
	conf.Set(configresolver.UserGlobalKey(name), &configresolver.LocalConfigField{
		Value:   value,
		Changed: true,
	})
}

// SetGlobalSystemDefault writes a value to UserGlobalKey unwrapped. Use for
// init metadata (device id, OS arch, runtime info, hover verbosity, output
// format, client protocol version, etc.) and CLI/process bootstrap paths
// (config-file path, log path, offline flag) that are not subject to
// LDX-Sync routing. The phase-2 wrap distinction has no effect on these
// settings today, so the raw write is sufficient.
func SetGlobalSystemDefault(conf configuration.Configuration, name string, value any) {
	conf.Set(configresolver.UserGlobalKey(name), value)
}

// SetGlobalDeferredFolderScope writes a value to UserGlobalKey unwrapped for
// settings that are folder-scoped per register_configurations.go but are still
// written at user-global today. Migrating these to the folder key requires
// folder-path threading through helper signatures (e.g. SetSeverityFilterOnConfig
// would gain a folder argument); the migration is tracked at IDE-1996. This
// helper exists so every such site is explicit at the callsite rather than
// hidden behind a raw conf.Set.
func SetGlobalDeferredFolderScope(conf configuration.Configuration, name string, value any) {
	conf.Set(configresolver.UserGlobalKey(name), value)
}

// SetGlobalRawForRawReader writes a value to UserGlobalKey unwrapped for
// settings whose reader is not wrap-aware. Currently this is SettingToken: the
// reader (config.GetToken) goes through raw conf.GetString, which would return
// the *LocalConfigField pointer formatted as a string if the write were
// wrapped. Migrating this site requires migrating GetToken at the same time.
func SetGlobalRawForRawReader(conf configuration.Configuration, name string, value any) {
	conf.Set(configresolver.UserGlobalKey(name), value)
}

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
	"reflect"
	"sync"
)

// SentConfigBaseline records the configuration values last sent to the IDE.
// On didChangeConfiguration, incoming values are compared against the baseline:
// if they match, the incoming update is treated as an IDE echo-back and ignored.
// All methods are safe for concurrent use.
type SentConfigBaseline struct {
	mu           sync.RWMutex
	folderValues map[FilePath]map[string]any // per-folder NullableField values sent via $/snyk.folderConfigs
	globalValues map[string]any              // global org-scope values sent via $/snyk.configuration
}

// NewSentConfigBaseline creates a new, empty SentConfigBaseline.
func NewSentConfigBaseline() *SentConfigBaseline {
	return &SentConfigBaseline{
		folderValues: make(map[FilePath]map[string]any),
		globalValues: make(map[string]any),
	}
}

// RecordFolderValue records the value that was sent to the IDE for the given
// folder path and setting name. Subsequent calls with the same path and name
// overwrite the previously recorded value.
func (b *SentConfigBaseline) RecordFolderValue(path FilePath, settingName string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.folderValues[path]
	if !ok {
		m = make(map[string]any)
		b.folderValues[path] = m
	}
	m[settingName] = value
}

// RecordGlobalValue records the global setting value that was sent to the IDE
// via $/snyk.configuration.
func (b *SentConfigBaseline) RecordGlobalValue(settingName string, value any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.globalValues[settingName] = value
}

// IsFolderEcho reports whether incoming matches the last value sent to the IDE
// for the given folder path and setting name. Returns false when no baseline
// entry exists (meaning no echo is possible).
func (b *SentConfigBaseline) IsFolderEcho(path FilePath, settingName string, incoming any) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	m, ok := b.folderValues[path]
	if !ok {
		return false
	}
	recorded, ok := m[settingName]
	if !ok {
		return false
	}
	return valuesEqualFor(settingName, incoming, recorded)
}

// IsGlobalEcho reports whether incoming matches the last global value sent to
// the IDE for the given setting name. Returns false when no baseline entry exists.
func (b *SentConfigBaseline) IsGlobalEcho(settingName string, incoming any) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	recorded, ok := b.globalValues[settingName]
	if !ok {
		return false
	}
	return valuesEqualFor(settingName, incoming, recorded)
}

// ClearFolder removes all baseline entries for the given folder path.
// Call this when a folder is removed from the workspace.
func (b *SentConfigBaseline) ClearFolder(path FilePath) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.folderValues, path)
}

// valuesEqualFor compares two values for the given setting name using the
// type-coercing equality function from the setting registry when available,
// falling back to reflect.DeepEqual.
func valuesEqualFor(settingName string, a, b any) bool {
	if cmp, ok := valuesEqualByName[settingName]; ok {
		return cmp(a, b)
	}
	return reflect.DeepEqual(a, b)
}

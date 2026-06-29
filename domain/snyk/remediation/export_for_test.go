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

package remediation

import "github.com/snyk/snyk-ls/internal/types"

// ExportedWorkspaceEditFromContent exposes workspaceEditFromContent for
// black-box tests in the remediation_test package.
func ExportedWorkspaceEditFromContent(absPath string, originalContent []byte, diff string) (*types.WorkspaceEdit, error) {
	return workspaceEditFromContent(absPath, originalContent, diff)
}

// InjectCacheEntry inserts a synthetic cache entry into the provider's cache
// for testing. changes maps file paths to TextEdits; storedHashes maps file
// paths to pre-computed hashes. Pass an empty storedHashes map to simulate
// the case where hash recording failed at populate time (e.g. the file was
// unreadable). The provider must have been constructed via NewRemyProvider.
// Keys in the injected storedHashes map should be a subset of the changes-map
// keys; any extra hash keys beyond those in changes are unreachable and ignored.
func InjectCacheEntry(p RemediationProvider, root string, changes map[string][]types.TextEdit, storedHashes map[string]string) {
	rp := p.(*remyProvider)
	rp.cacheMu.Lock()
	defer rp.cacheMu.Unlock()
	rp.cache[root] = &remyCacheEntry{
		changes:    changes,
		fileHashes: storedHashes,
	}
}

// CacheLen returns the number of root entries currently held in the provider's
// cache. It is used by tests to assert that populateCache did not store an
// empty entry (Change 2: ghost-entry fix).
func CacheLen(p RemediationProvider) int {
	rp := p.(*remyProvider)
	rp.cacheMu.Lock()
	defer rp.cacheMu.Unlock()
	return len(rp.cache)
}

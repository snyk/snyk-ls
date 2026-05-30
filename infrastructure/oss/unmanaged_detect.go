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

package oss

import (
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
)

// cppArtefactCache memoizes HasCPPArtefacts results for the lifetime of the
// process. C/C++ artefacts rarely appear/disappear within a session and a full
// WalkDir per folder per panel render would be wasteful.
var (
	cppArtefactCache   = make(map[string]bool)
	cppArtefactCacheMu sync.RWMutex
)

// HasCPPArtefactsCached returns the cached HasCPPArtefacts result for root,
// running the detector on a cache miss. Safe for concurrent use. Clear with
// ClearCPPArtefactCache (e.g. after a workspace folder change).
func HasCPPArtefactsCached(root string) bool {
	if root == "" {
		return false
	}
	cppArtefactCacheMu.RLock()
	v, ok := cppArtefactCache[root]
	cppArtefactCacheMu.RUnlock()
	if ok {
		return v
	}
	result := HasCPPArtefacts(root)
	cppArtefactCacheMu.Lock()
	cppArtefactCache[root] = result
	cppArtefactCacheMu.Unlock()
	return result
}

// ClearCPPArtefactCache removes all cached detection results. Primarily for tests.
func ClearCPPArtefactCache() {
	cppArtefactCacheMu.Lock()
	cppArtefactCache = make(map[string]bool)
	cppArtefactCacheMu.Unlock()
}

const (
	cppDetectMaxFiles = 5000
	cppDetectMaxDepth = 6
)

var cppFileExtensions = map[string]bool{
	".c":   true,
	".cc":  true,
	".cpp": true,
	".cxx": true,
	".c++": true,
	".h":   true,
	".hh":  true,
	".hpp": true,
	".hxx": true,
	".h++": true,
	".ipp": true,
	".tpp": true,
	".tcc": true,
	".inl": true,
}

var cppArtefactNames = map[string]bool{
	"CMakeLists.txt": true,
	"Makefile":       true,
	"makefile":       true,
	"configure.ac":   true,
	"configure.in":   true,
	"meson.build":    true,
}

var skipDirNames = map[string]bool{
	".git":             true,
	".svn":             true,
	".hg":              true,
	".idea":            true,
	".vscode":          true,
	"node_modules":     true,
	"vendor":           true,
	"bower_components": true,
	"dist":             true,
	"build":            true,
	"out":              true,
	"target":           true,
}

// HasCPPArtefacts walks root looking for any C/C++ source, header, or
// build-system file. It short-circuits on the first hit and is bounded by
// cppDetectMaxFiles and cppDetectMaxDepth so it is safe to call on the hot
// path of an OSS scan. Returns false if root does not exist or is unreadable.
func HasCPPArtefacts(root string) bool {
	if root == "" {
		return false
	}
	seen := 0
	found := false
	rootDepth := strings.Count(filepath.Clean(root), string(filepath.Separator))

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found || seen >= cppDetectMaxFiles {
			return fs.SkipAll
		}
		seen++

		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if skipDirNames[name] || strings.HasPrefix(name, "cmake-build-") {
				return fs.SkipDir
			}
			depth := strings.Count(filepath.Clean(path), string(filepath.Separator)) - rootDepth
			if depth > cppDetectMaxDepth {
				return fs.SkipDir
			}
			return nil
		}

		name := d.Name()
		if cppArtefactNames[name] {
			found = true
			return fs.SkipAll
		}
		if strings.HasSuffix(name, ".mk") {
			found = true
			return fs.SkipAll
		}
		ext := strings.ToLower(filepath.Ext(name))
		if cppFileExtensions[ext] {
			found = true
			return fs.SkipAll
		}
		return nil
	})

	return found
}

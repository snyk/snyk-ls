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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasCPPArtefacts(t *testing.T) {
	t.Run("empty root returns false", func(t *testing.T) {
		assert.False(t, HasCPPArtefacts(""))
	})

	t.Run("missing dir returns false", func(t *testing.T) {
		assert.False(t, HasCPPArtefacts(filepath.Join(t.TempDir(), "does-not-exist")))
	})

	t.Run("positive on .cpp file", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.cpp"), []byte("int main(){}"), 0o600))
		assert.True(t, HasCPPArtefacts(dir))
	})

	t.Run("positive on .h file in subdir", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "include")
		require.NoError(t, os.MkdirAll(sub, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(sub, "lib.h"), []byte("#pragma once"), 0o600))
		assert.True(t, HasCPPArtefacts(dir))
	})

	t.Run("positive on CMakeLists.txt", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "CMakeLists.txt"), []byte("project(x)"), 0o600))
		assert.True(t, HasCPPArtefacts(dir))
	})

	t.Run("positive on rules.mk", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.mk"), []byte("CC=gcc"), 0o600))
		assert.True(t, HasCPPArtefacts(dir))
	})

	t.Run("negative on JS-only folder", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.js"), []byte("console.log(1)"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o600))
		assert.False(t, HasCPPArtefacts(dir))
	})

	t.Run("ignores .cpp file inside node_modules", func(t *testing.T) {
		dir := t.TempDir()
		nm := filepath.Join(dir, "node_modules", "native-mod")
		require.NoError(t, os.MkdirAll(nm, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nm, "binding.cpp"), []byte("//"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.js"), []byte("// js"), 0o600))
		assert.False(t, HasCPPArtefacts(dir), "node_modules must be skipped")
	})

	t.Run("ignores .c file inside cmake-build-debug", func(t *testing.T) {
		dir := t.TempDir()
		sub := filepath.Join(dir, "cmake-build-debug", "generated")
		require.NoError(t, os.MkdirAll(sub, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(sub, "gen.c"), []byte("//"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("docs"), 0o600))
		assert.False(t, HasCPPArtefacts(dir), "cmake-build-* dirs must be skipped")
	})

	t.Run("finds .cpp at exactly cppDetectMaxDepth", func(t *testing.T) {
		dir := t.TempDir()
		deep := dir
		for range cppDetectMaxDepth {
			deep = filepath.Join(deep, "d")
		}
		require.NoError(t, os.MkdirAll(deep, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(deep, "lib.cpp"), []byte("//"), 0o600))
		assert.True(t, HasCPPArtefacts(dir), "files at exactly the max depth must still be discovered")
	})

	t.Run("ignores .cpp beyond cppDetectMaxDepth", func(t *testing.T) {
		dir := t.TempDir()
		// One level deeper than cppDetectMaxDepth — the directory should be skipped
		// before the .cpp inside it is ever read.
		deep := dir
		for range cppDetectMaxDepth + 1 {
			deep = filepath.Join(deep, "d")
		}
		require.NoError(t, os.MkdirAll(deep, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(deep, "lib.cpp"), []byte("//"), 0o600))
		assert.False(t, HasCPPArtefacts(dir), "directories deeper than cppDetectMaxDepth must be skipped")
	})
}

func TestHasCPPArtefactsCached(t *testing.T) {
	t.Run("returns the same result as the uncached detector", func(t *testing.T) {
		ClearCPPArtefactCache()
		t.Cleanup(ClearCPPArtefactCache)
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "main.c"), []byte("int main(){}"), 0o600))
		assert.True(t, HasCPPArtefactsCached(dir))

		jsDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(jsDir, "index.js"), []byte("//"), 0o600))
		assert.False(t, HasCPPArtefactsCached(jsDir))
	})

	t.Run("memoizes — subsequent calls return cached value even if the disk changes", func(t *testing.T) {
		ClearCPPArtefactCache()
		t.Cleanup(ClearCPPArtefactCache)
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "index.js"), []byte("//"), 0o600))
		assert.False(t, HasCPPArtefactsCached(dir), "first call: JS only → false")

		// Add a .c file AFTER the cache miss — the cached value should still be false.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "added.c"), []byte("//"), 0o600))
		assert.False(t, HasCPPArtefactsCached(dir), "cache should be returned, not re-scanned")

		// After clearing, the fresh scan should see the .c file.
		ClearCPPArtefactCache()
		assert.True(t, HasCPPArtefactsCached(dir), "after clear, fresh scan picks up new files")
	})

	t.Run("empty root short-circuits", func(t *testing.T) {
		ClearCPPArtefactCache()
		t.Cleanup(ClearCPPArtefactCache)
		assert.False(t, HasCPPArtefactsCached(""))
	})
}

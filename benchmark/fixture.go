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

// Package benchmark holds performance benchmarks and a generated monorepo fixture.
package benchmark

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Counts match the IDE-1940 megaproject simulation (500 Snyk Code + 500 OSS leaves).
const (
	CodeFolderCount = 500
	OSSFolderCount  = 500
)

//go:embed testdata/code_template.js testdata/oss_package.json testdata/oss_package-lock.json
var templateFS embed.FS

// GenerateMonorepoFixture materializes code_* and oss_* folders under root using embedded templates.
func GenerateMonorepoFixture(tb testing.TB, root string) error {
	tb.Helper()
	return generateMonorepoFixture(tb, root, CodeFolderCount, OSSFolderCount)
}

// GenerateMonorepoFixtureCounts materializes code_* and oss_* folders with the given folder counts (same logic as [GenerateMonorepoFixture], scaled).
func GenerateMonorepoFixtureCounts(tb testing.TB, root string, codeFolders, ossFolders int) error {
	tb.Helper()
	return generateMonorepoFixture(tb, root, codeFolders, ossFolders)
}

func generateMonorepoFixture(tb testing.TB, root string, codeFolders, ossFolders int) error {
	tb.Helper()

	codeTemplate, err := templateFS.ReadFile("testdata/code_template.js")
	if err != nil {
		return fmt.Errorf("read code template: %w", err)
	}
	ossPkg, err := templateFS.ReadFile("testdata/oss_package.json")
	if err != nil {
		return fmt.Errorf("read oss package.json template: %w", err)
	}
	ossLock, err := templateFS.ReadFile("testdata/oss_package-lock.json")
	if err != nil {
		return fmt.Errorf("read oss package-lock template: %w", err)
	}

	for i := range codeFolders {
		dir := filepath.Join(root, fmt.Sprintf("code_%03d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		path := filepath.Join(dir, "index.js")
		if err := os.WriteFile(path, codeTemplate, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	for i := range ossFolders {
		dir := filepath.Join(root, fmt.Sprintf("oss_%03d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		pj := filepath.Join(dir, "package.json")
		if err := os.WriteFile(pj, ossPkg, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", pj, err)
		}
		pl := filepath.Join(dir, "package-lock.json")
		if err := os.WriteFile(pl, ossLock, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", pl, err)
		}
	}

	return nil
}

// WalkMonorepoFixture walks root and invokes fn for every file (not directories).
func WalkMonorepoFixture(root string, fn func(path string, d fs.DirEntry) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		return fn(path, d)
	})
}

// AssertMonorepoFixtureLayout checks that root contains exactly codeFolders code_* directories
// and ossFolders oss_* directories, each with the expected leaf files. Other entries at root
// (for example .git after git init) are ignored.
func AssertMonorepoFixtureLayout(tb testing.TB, root string, codeFolders, ossFolders int) {
	tb.Helper()
	codeDirs, ossDirs := readMonorepoFixtureDirCounts(tb, root)
	if codeDirs != codeFolders {
		tb.Fatalf("monorepo fixture code_* dirs: got %d want %d under %s", codeDirs, codeFolders, root)
	}
	if ossDirs != ossFolders {
		tb.Fatalf("monorepo fixture oss_* dirs: got %d want %d under %s", ossDirs, ossFolders, root)
	}
	assertMonorepoCodeLeaves(tb, root, codeFolders)
	assertMonorepoOSSLeaves(tb, root, ossFolders)
}

func readMonorepoFixtureDirCounts(tb testing.TB, root string) (codeDirs, ossDirs int) {
	tb.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		tb.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			tb.Fatalf("unexpected file at fixture root: %s", e.Name())
		}
		name := e.Name()
		if name == ".git" {
			continue
		}
		switch {
		case strings.HasPrefix(name, "code_"):
			codeDirs++
		case strings.HasPrefix(name, "oss_"):
			ossDirs++
		default:
			tb.Fatalf("unexpected directory at fixture root: %s", name)
		}
	}
	return codeDirs, ossDirs
}

func assertMonorepoCodeLeaves(tb testing.TB, root string, codeFolders int) {
	tb.Helper()
	for i := range codeFolders {
		dir := filepath.Join(root, fmt.Sprintf("code_%03d", i))
		js := filepath.Join(dir, "index.js")
		if st, err := os.Stat(js); err != nil || st.IsDir() {
			tb.Fatalf("missing index.js under %s: %v", dir, err)
		}
	}
}

func assertMonorepoOSSLeaves(tb testing.TB, root string, ossFolders int) {
	tb.Helper()
	for i := range ossFolders {
		dir := filepath.Join(root, fmt.Sprintf("oss_%03d", i))
		for _, f := range []string{"package.json", "package-lock.json"} {
			p := filepath.Join(dir, f)
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				tb.Fatalf("missing %s under %s: %v", f, dir, err)
			}
		}
	}
}

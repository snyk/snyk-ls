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

package server

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
)

// sharedGoofDir is the path to a single nodejs-goof clone shared across all smoke tests.
// It is populated by TestMain when SMOKE_TESTS=1 and is read-only — tests must call
// copyGoofDir to get a writable per-test copy before using it as a workspace.
var sharedGoofDir types.FilePath

// TestSharedGoofDirIsPopulated asserts that TestMain correctly seeds sharedGoofDir.
// This test fails when run with SMOKE_TESTS=1 before TestMain is implemented.
func TestSharedGoofDirIsPopulated(t *testing.T) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" {
		t.Skipf("set %s=1 to run shared-clone validation", testsupport.SmokeTestEnvVar)
	}
	assert.NotEmpty(t, string(sharedGoofDir), "sharedGoofDir must be set by TestMain when SMOKE_TESTS=1")
	_, err := os.Stat(filepath.Join(string(sharedGoofDir), "package.json"))
	assert.NoError(t, err, "package.json must exist in sharedGoofDir")
}

// TestMain clones nodejs-goof once for the whole package test run when SMOKE_TESTS=1.
// All smoke tests that need goof call copyGoofDir(t) to get a fast local copy.
func TestMain(m *testing.M) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" {
		os.Exit(m.Run())
	}

	dir, err := cloneGoofOnce()
	if err != nil {
		log.Fatalf("shared goof clone failed: %v", err)
	}
	sharedGoofDir = dir

	code := m.Run()
	os.RemoveAll(string(dir))
	os.Exit(code)
}

// cloneGoofOnce performs a single git clone of nodejs-goof into a temp directory.
// The returned path is the repo root (contains package.json, app.js, etc.).
func cloneGoofOnce() (types.FilePath, error) {
	base, err := os.MkdirTemp("", "snyk-ls-goof-shared-*")
	if err != nil {
		return "", err
	}

	for _, args := range [][]string{
		{"clone", "-v", testsupport.NodejsGoof, "goof"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = base
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			os.RemoveAll(base)
			return "", cmdErr
		} else {
			log.Printf("shared goof clone: git %v\n%s", args, out)
		}
	}

	goofDir := filepath.Join(base, "goof")
	for _, args := range [][]string{
		{"reset", "--hard", "0336589"},
		{"clean", "--force"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = goofDir
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			os.RemoveAll(base)
			return "", cmdErr
		} else {
			log.Printf("shared goof clone: git %v\n%s", args, out)
		}
	}

	return types.FilePath(goofDir), nil
}

// copyGoofDir returns a writable per-test copy of sharedGoofDir via a fast local
// git clone into a new t.TempDir(). If sharedGoofDir is not set (e.g. when running
// a single smoke test outside TestMain), it falls back to a fresh network clone.
//
// Use copyGoofDirInto when the destination must be a pre-allocated directory (e.g. to
// preserve LIFO t.Cleanup ordering that keeps the server alive until the dir is gone).
func copyGoofDir(t *testing.T) types.FilePath {
	t.Helper()
	return copyGoofDirInto(t, t.TempDir())
}

// copyGoofDirInto copies sharedGoofDir into dest and returns the goof sub-path.
// dest must already exist; its cleanup is the caller's responsibility.
// Using a pre-allocated dest (registered before setupServer) preserves the correct
// LIFO t.Cleanup order on Windows: server shuts down before dest is removed.
func copyGoofDirInto(t *testing.T, dest string) types.FilePath {
	t.Helper()
	if sharedGoofDir == "" {
		t.Log("sharedGoofDir not set — falling back to network clone (slow path)")
		cmd := exec.Command("git", "clone", "-v", testsupport.NodejsGoof, "goof")
		cmd.Dir = dest
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("copyGoofDirInto: git clone: %v\n%s", err, out)
		}
		goofDir := filepath.Join(dest, "goof")
		for _, args := range [][]string{{"reset", "--hard", "0336589"}, {"clean", "--force"}} {
			cmd = exec.Command("git", args...)
			cmd.Dir = goofDir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("copyGoofDirInto: git %v: %v\n%s", args, err, out)
			}
		}
		return types.FilePath(goofDir)
	}

	// git clone --local creates a copy with hardlinks — much faster than a network clone.
	cmd := exec.Command("git", "clone", "--local", "--no-hardlinks", string(sharedGoofDir), "goof")
	cmd.Dir = dest
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copyGoofDirInto: git clone --local: %v\n%s", err, out)
	}
	return types.FilePath(filepath.Join(dest, "goof"))
}

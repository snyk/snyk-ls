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
	"context"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// sharedGoofCommit is the nodejs-goof commit checked out by cloneGoofOnce.
// setupRepoAndInitializeInDir guards that callers pass this same commit so they
// don't silently receive wrong repo state.
const sharedGoofCommit = "0336589"

// sharedGoofDir is the path to a single nodejs-goof clone shared across all smoke tests.
// It is populated by TestMain when SMOKE_TESTS=1 and is read-only — tests must call
// copyGoofDir to get a writable per-test copy before using it as a workspace.
var sharedGoofDir types.FilePath

// sharedCLIPath is the path to a single Snyk CLI binary shared across all smoke tests.
// It is populated by TestMain when SMOKE_TESTS=1. Tests must not delete or overwrite it.
var sharedCLIPath string

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

// TestSharedCLIPathIsPopulated asserts that TestMain correctly seeds sharedCLIPath.
func TestSharedCLIPathIsPopulated(t *testing.T) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" {
		t.Skipf("set %s=1 to run shared-CLI validation", testsupport.SmokeTestEnvVar)
	}
	assert.NotEmpty(t, sharedCLIPath, "sharedCLIPath must be set by TestMain when SMOKE_TESTS=1")
	_, err := os.Stat(sharedCLIPath)
	assert.NoError(t, err, "CLI binary must exist at sharedCLIPath")
}

// TestMain clones nodejs-goof and downloads the Snyk CLI once for the whole package
// test run when SMOKE_TESTS=1. All smoke tests that need goof call copyGoofDir(t) to
// get a fast local copy. setUniqueCliPath reuses sharedCLIPath to avoid re-downloading.
func TestMain(m *testing.M) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" {
		os.Exit(m.Run())
	}

	base, err := cloneGoofOnce()
	if err != nil {
		log.Fatalf("shared goof clone failed: %v", err)
	}
	sharedGoofDir = types.FilePath(filepath.Join(string(base), "goof"))

	cliDir, err := os.MkdirTemp("", "snyk-ls-cli-shared-*")
	if err != nil {
		log.Fatalf("shared CLI temp dir failed: %v", err)
	}
	engine, err := testutil.NewMinimalEngine()
	if err != nil {
		log.Fatalf("shared CLI engine init failed: %v", err)
	}
	sharedCLIPath, err = downloadCLI(engine, cliDir)
	if err != nil {
		log.Fatalf("shared CLI download failed: %v", err)
	}
	log.Printf("shared CLI downloaded to: %s", sharedCLIPath)

	code := m.Run()
	os.RemoveAll(string(base))
	os.RemoveAll(cliDir)
	os.Exit(code)
}

// downloadCLI downloads the Snyk CLI binary into cliDir using the provided engine's
// installer. It configures SettingCliPath and SettingAutomaticDownload, calls the
// installer, and returns the installed binary path.
func downloadCLI(engine workflow.Engine, cliDir string) (string, error) {
	conf := engine.GetConfiguration()
	discovery := &install.Discovery{}
	cliPath := filepath.Join(cliDir, discovery.ExecutableName(false))
	conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticDownload), true)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	er := error_reporting.NewTestErrorReporter(engine)
	resolver := testutil.DefaultConfigResolver(engine)
	installer := install.NewInstaller(engine, er, func() *http.Client { return http.DefaultClient }, resolver)
	return installer.Install(ctx)
}

// cloneGoofOnce performs a single git clone of nodejs-goof into a temp directory.
// The returned path is the base temp directory; the repo root lives at base/goof.
func cloneGoofOnce() (types.FilePath, error) {
	base, err := os.MkdirTemp("", "snyk-ls-goof-shared-*")
	if err != nil {
		return "", err
	}

	cloneCmd := exec.Command("git", "clone", "-v", testsupport.NodejsGoof, "goof")
	cloneCmd.Dir = base
	cloneCmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	if out, cmdErr := cloneCmd.CombinedOutput(); cmdErr != nil {
		os.RemoveAll(base)
		return "", cmdErr
	} else {
		log.Printf("shared goof clone: git clone\n%s", out)
	}

	goofDir := filepath.Join(base, "goof")
	for _, args := range [][]string{
		{"reset", "--hard", sharedGoofCommit},
		{"clean", "--force"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = goofDir
		cmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			os.RemoveAll(base)
			return "", cmdErr
		} else {
			log.Printf("shared goof clone: git %v\n%s", args, out)
		}
	}

	return types.FilePath(base), nil
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
	gitEnv := testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	if sharedGoofDir == "" {
		t.Log("sharedGoofDir not set — falling back to network clone (slow path)")
		cmd := exec.Command("git", "clone", "-v", testsupport.NodejsGoof, "goof")
		cmd.Dir = dest
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("copyGoofDirInto: git clone: %v\n%s", err, out)
		}
		goofDir := filepath.Join(dest, "goof")
		for _, args := range [][]string{{"reset", "--hard", sharedGoofCommit}, {"clean", "--force"}} {
			cmd = exec.Command("git", args...)
			cmd.Dir = goofDir
			cmd.Env = gitEnv
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
	cmd.Env = gitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copyGoofDirInto: git clone --local: %v\n%s", err, out)
	}
	goofCopy := filepath.Join(dest, "goof")
	// Restore the real GitHub remote URL so tools that query origin (e.g. LDX-sync) see the
	// canonical repo URL rather than the local sharedGoofDir path set by git clone --local.
	setURL := exec.Command("git", "remote", "set-url", "origin", testsupport.NodejsGoof)
	setURL.Dir = goofCopy
	setURL.Env = gitEnv
	if out, err := setURL.CombinedOutput(); err != nil {
		t.Fatalf("copyGoofDirInto: git remote set-url: %v\n%s", err, out)
	}
	return types.FilePath(goofCopy)
}

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

// snykconGoofURL is the URL of the snykcon-goof repo used by IaC+Code smoke tests.
const snykconGoofURL = "https://github.com/deepcodeg/snykcon-goof.git"

// sharedSnykconGoofCommit is the snykcon-goof commit checked out by TestMain.
const sharedSnykconGoofCommit = "eba8407"

// sharedFakeLeaksCommit is the fake-leaks commit; empty means clone HEAD.
const sharedFakeLeaksCommit = ""

// sharedGoofDir is the path to a single nodejs-goof clone shared across all smoke tests.
// It is populated by TestMain when SMOKE_TESTS=1 and is read-only — tests must call
// copyGoofDir to get a writable per-test copy before using it as a workspace.
var sharedGoofDir types.FilePath

// sharedSnykconGoofDir is the path to a single snykcon-goof clone shared across all smoke tests.
// It is populated by TestMain when SMOKE_TESTS=1 and is read-only — tests must call
// copySnykconGoofDirInto to get a writable per-test copy before using it as a workspace.
var sharedSnykconGoofDir types.FilePath

// sharedFakeLeaksDir is the path to a single fake-leaks clone shared across all smoke tests.
var sharedFakeLeaksDir types.FilePath

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

// TestSharedSnykconGoofDirIsPopulated asserts that TestMain correctly seeds sharedSnykconGoofDir.
func TestSharedSnykconGoofDirIsPopulated(t *testing.T) {
	if os.Getenv(testsupport.SmokeTestEnvVar) == "" {
		t.Skipf("set %s=1 to run shared-clone validation", testsupport.SmokeTestEnvVar)
	}
	assert.NotEmpty(t, string(sharedSnykconGoofDir), "sharedSnykconGoofDir must be set by TestMain when SMOKE_TESTS=1")
	_, err := os.Stat(filepath.Join(string(sharedSnykconGoofDir), "main.tf"))
	assert.NoError(t, err, "main.tf must exist in sharedSnykconGoofDir")
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

	base, err := cloneRepoOnce("snyk-ls-goof-shared-*", testsupport.NodejsGoof, "goof", sharedGoofCommit)
	if err != nil {
		log.Fatalf("shared goof clone failed: %v", err)
	}
	sharedGoofDir = types.FilePath(filepath.Join(string(base), "goof"))

	snykconBase, err := cloneRepoOnce("snyk-ls-snykcon-shared-*", snykconGoofURL, "snykcon-goof", sharedSnykconGoofCommit)
	if err != nil {
		log.Fatalf("shared snykcon-goof clone failed: %v", err)
	}
	sharedSnykconGoofDir = types.FilePath(filepath.Join(string(snykconBase), "snykcon-goof"))

	fakeLeaksBase, err := cloneRepoOnce("snyk-ls-fakeleaks-shared-*", testsupport.FakeLeaks, "fake-leaks", sharedFakeLeaksCommit)
	if err != nil {
		log.Fatalf("shared fake-leaks clone failed: %v", err)
	}
	sharedFakeLeaksDir = types.FilePath(filepath.Join(string(fakeLeaksBase), "fake-leaks"))

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
	os.RemoveAll(string(snykconBase))
	os.RemoveAll(string(fakeLeaksBase))
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

// cloneRepoOnce clones url into tmpPrefix/subdir, resets to commit, and returns the base temp dir.
func cloneRepoOnce(tmpPrefix, url, subdir, commit string) (types.FilePath, error) {
	base, err := os.MkdirTemp("", tmpPrefix)
	if err != nil {
		return "", err
	}

	cloneCmd := exec.Command("git", "clone", "-v", url, subdir)
	cloneCmd.Dir = base
	cloneCmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	if out, cmdErr := cloneCmd.CombinedOutput(); cmdErr != nil {
		os.RemoveAll(base)
		return "", cmdErr
	} else {
		log.Printf("shared %s clone: git clone\n%s", subdir, out)
	}

	repoDir := filepath.Join(base, subdir)
	var postCloneSteps [][]string
	if commit != "" {
		postCloneSteps = append(postCloneSteps, []string{"reset", "--hard", commit})
	}
	postCloneSteps = append(postCloneSteps, []string{"clean", "--force"})
	for _, args := range postCloneSteps {
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		cmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			os.RemoveAll(base)
			return "", cmdErr
		} else {
			log.Printf("shared %s clone: git %v\n%s", subdir, args, out)
		}
	}

	return types.FilePath(base), nil
}

// copyFakeLeaksDirInto copies sharedFakeLeaksDir into dest and returns the repo sub-path.
// Falls back to a network clone when sharedFakeLeaksDir is not set.
func copyFakeLeaksDirInto(t *testing.T, dest string) types.FilePath {
	t.Helper()
	gitEnv := testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	if sharedFakeLeaksDir == "" {
		t.Log("sharedFakeLeaksDir not set — falling back to network clone (slow path)")
		cmd := exec.Command("git", "clone", "-v", testsupport.FakeLeaks, "fake-leaks")
		cmd.Dir = dest
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("copyFakeLeaksDirInto: git clone: %v\n%s", err, out)
		}
		return types.FilePath(filepath.Join(dest, "fake-leaks"))
	}

	cmd := exec.Command("git", "clone", "--local", "--no-hardlinks", string(sharedFakeLeaksDir), "fake-leaks")
	cmd.Dir = dest
	cmd.Env = gitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copyFakeLeaksDirInto: git clone --local: %v\n%s", err, out)
	}
	repoCopy := filepath.Join(dest, "fake-leaks")
	setURL := exec.Command("git", "remote", "set-url", "origin", testsupport.FakeLeaks)
	setURL.Dir = repoCopy
	setURL.Env = gitEnv
	if out, err := setURL.CombinedOutput(); err != nil {
		t.Fatalf("copyFakeLeaksDirInto: git remote set-url: %v\n%s", err, out)
	}
	return types.FilePath(repoCopy)
}

// copySnykconGoofDirInto copies sharedSnykconGoofDir into dest and returns the repo sub-path.
// dest must already exist; its cleanup is the caller's responsibility.
// Falls back to a network clone when sharedSnykconGoofDir is not set (single-test run outside TestMain).
func copySnykconGoofDirInto(t *testing.T, dest string) types.FilePath {
	t.Helper()
	gitEnv := testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	if sharedSnykconGoofDir == "" {
		t.Log("sharedSnykconGoofDir not set — falling back to network clone (slow path)")
		cmd := exec.Command("git", "clone", "-v", snykconGoofURL, "snykcon-goof")
		cmd.Dir = dest
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("copySnykconGoofDirInto: git clone: %v\n%s", err, out)
		}
		repoDir := filepath.Join(dest, "snykcon-goof")
		for _, args := range [][]string{{"reset", "--hard", sharedSnykconGoofCommit}, {"clean", "--force"}} {
			cmd = exec.Command("git", args...)
			cmd.Dir = repoDir
			cmd.Env = gitEnv
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("copySnykconGoofDirInto: git %v: %v\n%s", args, err, out)
			}
		}
		return types.FilePath(repoDir)
	}

	cmd := exec.Command("git", "clone", "--local", "--no-hardlinks", string(sharedSnykconGoofDir), "snykcon-goof")
	cmd.Dir = dest
	cmd.Env = gitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copySnykconGoofDirInto: git clone --local: %v\n%s", err, out)
	}
	repoCopy := filepath.Join(dest, "snykcon-goof")
	setURL := exec.Command("git", "remote", "set-url", "origin", snykconGoofURL)
	setURL.Dir = repoCopy
	setURL.Env = gitEnv
	if out, err := setURL.CombinedOutput(); err != nil {
		t.Fatalf("copySnykconGoofDirInto: git remote set-url: %v\n%s", err, out)
	}
	return types.FilePath(repoCopy)
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

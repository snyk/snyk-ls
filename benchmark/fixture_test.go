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

package benchmark

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
)

func TestGenerateMonorepoFixture_Smoke(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const n = 2
	if err := GenerateMonorepoFixtureCounts(t, root, n, n); err != nil {
		t.Fatal(err)
	}
	AssertMonorepoFixtureLayout(t, root, n, n)
}

func TestGenerateMonorepoFixtureCounts_CustomDimensions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const codeN, ossN = 3, 5
	if err := GenerateMonorepoFixtureCounts(t, root, codeN, ossN); err != nil {
		t.Fatal(err)
	}
	AssertMonorepoFixtureLayout(t, root, codeN, ossN)
}

func gitCommandForFixtureTest(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testsupport.GitEnvWithoutInheritedRepoConfig(os.Environ())
	return cmd
}

// TestGenerateMonorepoFixture_ProductionScale requires FULL_FIXTURE_VERIFY=1 (writes ~390 MiB).
func TestGenerateMonorepoFixture_ProductionScale(t *testing.T) {
	if os.Getenv("FULL_FIXTURE_VERIFY") != "1" {
		t.Skip("set FULL_FIXTURE_VERIFY=1 to run the 500+500 disk-heavy layout check")
	}
	root := t.TempDir()
	if err := GenerateMonorepoFixture(t, root); err != nil {
		t.Fatal(err)
	}
	AssertMonorepoFixtureLayout(t, root, CodeFolderCount, OSSFolderCount)
}

func TestAssertMonorepoFixtureLayout_IgnoresGitDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const n = 2
	if err := GenerateMonorepoFixtureCounts(t, root, n, n); err != nil {
		t.Fatal(err)
	}
	cmd := gitCommandForFixtureTest(root, "init", "--initial-branch=main")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	AssertMonorepoFixtureLayout(t, root, n, n)
}

func TestGenerateMonorepoFixtureCounts_CleansCreatedDirsOnFailure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "oss_000"), []byte("not a directory"), 0o644))

	err := GenerateMonorepoFixtureCounts(t, root, 1, 1)

	require.Error(t, err)
	require.NoDirExists(t, filepath.Join(root, "code_000"))
	require.FileExists(t, filepath.Join(root, "oss_000"))
}

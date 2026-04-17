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
	"testing"
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
	cmd := exec.Command("git", "init", "--initial-branch=main")
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	AssertMonorepoFixtureLayout(t, root, n, n)
}

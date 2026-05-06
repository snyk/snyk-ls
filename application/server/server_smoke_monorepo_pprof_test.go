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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/benchmark"
)

// Tests in this file must not use t.Parallel: runtime/pprof CPU profiling is process-global (StartCPUProfile).

func Test_withMonorepoRealScanPprof_NoDirRunsBody(t *testing.T) {
	var ran int
	withMonorepoRealScanPprof(t, "", func() { ran++ })
	require.Equal(t, 1, ran)
}

func Test_withMonorepoRealScanPprof_WritesProfiles(t *testing.T) {
	dir := t.TempDir()
	withMonorepoRealScanPprof(t, dir, func() {})

	cpu := filepath.Join(dir, monorepoRealScanProfileCPU)
	heapBefore := filepath.Join(dir, monorepoRealScanProfileHeapBefore)
	heapAfter := filepath.Join(dir, monorepoRealScanProfileHeapAfter)

	st, err := os.Stat(cpu)
	require.NoError(t, err)
	require.Positive(t, st.Size())

	for _, p := range []string{heapBefore, heapAfter} {
		st, err = os.Stat(p)
		require.NoError(t, err)
		require.Positive(t, st.Size())
	}

	heapSamples := filepath.Join(dir, monorepoRealScanProfileHeapSamples)
	hs, err := os.ReadFile(heapSamples)
	require.NoError(t, err)
	require.NotEmpty(t, hs)
	lines := strings.Split(strings.TrimSpace(string(hs)), "\n")
	require.GreaterOrEqual(t, len(lines), 3, "want header plus initial and final samples")
	require.Contains(t, lines[0], "unix_ns")
	require.Contains(t, lines[0], "heap_sys_bytes")
}

func Test_monorepoBenchmarkFixtureScale_FullFixtureEnv(t *testing.T) {
	t.Setenv("BENCHMARK_REALSCAN_FULL_FIXTURE", "1")

	codeFolders, ossFolders := monorepoBenchmarkFixtureScale(t)

	require.Equal(t, benchmark.CodeFolderCount, codeFolders)
	require.Equal(t, benchmark.OSSFolderCount, ossFolders)
}

func Test_initializeGitRepoForMonorepoBenchmark_IgnoresInheritedGitEnv(t *testing.T) {
	outerRepo := t.TempDir()
	cmd := exec.Command("git", "init")
	cmd.Dir = outerRepo
	require.NoError(t, cmd.Run())
	t.Setenv("GIT_DIR", filepath.Join(outerRepo, ".git"))
	t.Setenv("GIT_WORK_TREE", outerRepo)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "user.name")
	t.Setenv("GIT_CONFIG_VALUE_0", "Leaked User")

	repoDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "test.txt"), []byte("content"), 0o644))

	initializeGitRepoForMonorepoBenchmark(t, repoDir)

	require.DirExists(t, filepath.Join(repoDir, ".git"))
	cmd = gitCommandForMonorepoBenchmark(repoDir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	require.NoError(t, err)
	expectedRepoDir, err := filepath.EvalSymlinks(repoDir)
	require.NoError(t, err)
	actualRepoDir, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	require.NoError(t, err)
	require.Equal(t, expectedRepoDir, actualRepoDir)

	cmd = gitCommandForMonorepoBenchmark(repoDir, "config", "--get", "user.name")
	out, err = cmd.Output()
	require.NoError(t, err)
	require.Equal(t, "Test User", strings.TrimSpace(string(out)))
}

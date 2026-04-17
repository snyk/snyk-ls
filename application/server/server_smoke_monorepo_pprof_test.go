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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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
}

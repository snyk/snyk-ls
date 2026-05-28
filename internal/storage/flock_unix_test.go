//go:build !windows

/*
 * © 2023-2024 Snyk Limited
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

package storage

import (
	"os"
	"syscall"
	"testing"
)

// flockEnforced returns true when the OS/filesystem actually enforces exclusive
// file locks. Overlay filesystems (e.g. Docker) often treat flock as a no-op,
// which makes Test_ParallelFileLocking meaningless and spuriously slow.
func flockEnforced(t *testing.T) bool {
	t.Helper()
	f1, err := os.CreateTemp(t.TempDir(), "flock-probe-")
	if err != nil {
		return true // assume enforced if we can't probe
	}
	defer f1.Close()

	f2, err := os.Open(f1.Name())
	if err != nil {
		return true
	}
	defer f2.Close()

	if err = syscall.Flock(int(f1.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true // first lock failed — unusual, but treat as enforced
	}
	defer syscall.Flock(int(f1.Fd()), syscall.LOCK_UN)

	// If a second LOCK_EX|LOCK_NB on the same file succeeds, locks are not enforced.
	err = syscall.Flock(int(f2.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	return err != nil
}

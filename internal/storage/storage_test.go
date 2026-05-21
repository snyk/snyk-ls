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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testsupport"
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

func Test_StorageCallsRegisterCallbacksForKeys(t *testing.T) {
	called := make(chan bool, 1)
	callbacks := map[string]StorageCallbackFunc{}
	file := filepath.Join(t.TempDir(), testsupport.PathSafeTestName(t))
	myCallback := func(_ string, _ any) { called <- true }

	key := "test"
	value := "test"
	callbacks[key] = myCallback
	s, err := NewStorageWithCallbacks(WithCallbacks(callbacks), WithStorageFile(file))
	require.NoError(t, err)

	err = s.Set(key, value)

	require.NoError(t, err)
	require.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")
}

func Test_StorageCallsEmptyValueShouldCleanValueFromFile(t *testing.T) {
	called := make(chan bool, 1)
	callbacks := map[string]StorageCallbackFunc{}
	file := filepath.Join(t.TempDir(), testsupport.PathSafeTestName(t))
	myCallback := func(_ string, _ any) { called <- true }

	key := "test"
	value := "test"
	callbacks[key] = myCallback
	s, err := NewStorageWithCallbacks(WithCallbacks(callbacks), WithStorageFile(file))
	require.NoError(t, err)

	err = s.Set(key, value)

	require.NoError(t, err)
	require.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")

	content, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, "{\"test\":\"test\"}", string(content))

	err = s.Set(key, "")

	require.NoError(t, err)
	require.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")

	content, err = os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, "{\"test\":\"\"}", string(content))
}

func Test_StorageCallsRegisterCallbacks_InvalidJsonContent_ShouldClean(t *testing.T) {
	called := make(chan bool, 1)
	callbacks := map[string]StorageCallbackFunc{}
	file := filepath.Join(t.TempDir(), testsupport.PathSafeTestName(t))
	err := os.WriteFile(file, []byte("{\"INTERNAL_OAUTH_TOKEN_STORAGE\":\"{\\\"access_token\\\":\\\"mytoken\\\",\\\"token_type\\\":\\\"bearer\\\",\\\"refresh_token\\\":\\\"myrefreshtoken\\\",\\\"expiry\\\":\\\"2024-10-01T21:43:26.209852+02:00\\\"}\"}\"snyk_token\":\"\"}"), 0644)
	assert.NoError(t, err)
	myCallback := func(_ string, _ any) { called <- true }

	key := "testKey"
	value := "testValue"
	callbacks[key] = myCallback
	s, err := NewStorageWithCallbacks(WithCallbacks(callbacks), WithStorageFile(file))
	require.NoError(t, err)

	err = s.Set(key, value)
	require.NoError(t, err)
	content, err := os.ReadFile(file)
	assert.NoError(t, err)
	assert.Equal(t, "{\"testKey\":\"testValue\"}", string(content))
	require.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")
}

func Test_ParallelFileLocking(t *testing.T) {
	if !flockEnforced(t) {
		t.Skip("Skipping: filesystem does not enforce exclusive file locks (overlay fs)")
	}
	t.Run("should respect locking order", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), testsupport.PathSafeTestName(t))
		err := os.MkdirAll(filepath.Dir(file), 0755)
		require.NoError(t, err)
		err = os.WriteFile(file, []byte("{}"), 0644)
		require.NoError(t, err)

		// we should not get concurrent writes to the backing map here
		var parallelism = 100
		for i := 0; i < parallelism; i++ {
			go func(count int) {
				cut, _ := NewStorageWithCallbacks(WithStorageFile(file))

				lockErr := cut.Lock(t.Context(), time.Millisecond)
				require.NoError(t, lockErr)
				defer func() {
					unlockErr := cut.Unlock()
					require.NoError(t, unlockErr)
				}()

				err = cut.Set(fmt.Sprintf("test-%d", count), count)
				require.NoError(t, err)
			}(i)
		}

		assert.Eventually(t, func() bool {
			bytes, readErr := os.ReadFile(file)
			if readErr != nil {
				return false
			}
			var result map[string]any
			unmarshalErr := json.Unmarshal(bytes, &result)
			if unmarshalErr != nil {
				return false
			}

			return parallelism == len(result)
		}, time.Second*time.Duration(parallelism), time.Millisecond)
	})
}

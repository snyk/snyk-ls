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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StorageCallsRegisterCallbacksForKeys(t *testing.T) {
	called := make(chan bool, 1)
	callbacks := map[string]StorageCallbackFunc{}
	file := filepath.Join(t.TempDir(), t.Name())
	myCallback := func(_ string, _ any) { called <- true }

	key := "test"
	value := "test"
	callbacks[key] = myCallback
	s := NewStorage(WithCallbacks(callbacks), WithStorageFile(file)).(*storage)

	err := s.Set(key, value)

	assert.NoError(t, err)
	assert.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")
}

func Test_ParallelFileLocking(t *testing.T) {
	t.Run("should respect locking order", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), t.Name())
		err := os.MkdirAll(filepath.Dir(file), 0755)
		require.NoError(t, err)
		err = os.WriteFile(file, []byte("{}"), 0644)
		require.NoError(t, err)

		cut := NewStorage(WithStorageFile(file))

		// we should not get concurrent writes to the backing map here
		parallelism := 10
		for i := range parallelism {
			go func() {
				lockErr := cut.Lock(context.Background(), time.Millisecond*100)
				require.NoError(t, lockErr)
				defer func(cut StorageWithCallbacks) {
					unlockErr := cut.Unlock()
					require.NoError(t, unlockErr)
				}(cut)

				err = cut.Set(fmt.Sprintf("test-%d", i), i)

				require.NoError(t, err)
			}()
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
		}, time.Second*5, time.Second)
	})
}

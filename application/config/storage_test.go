/*
 * © 2023 Snyk Limited
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

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_StorageCallsRegisterCallbacksForKeys(t *testing.T) {
	called := make(chan bool, 1)
	callbacks := map[string]StorageCallbackFunc{}
	myCallback := func(_ string, _ any) { called <- true }

	key := "test"
	value := "test"
	callbacks[key] = myCallback
	s := NewStorage(WithCallbacks(callbacks)).(*storage)

	err := s.Set(key, value)

	assert.NoError(t, err)
	assert.Equal(t, value, s.data[key])
	assert.Eventuallyf(t, func() bool {
		return <-called
	}, 5*time.Second, time.Millisecond, "callback was not called")
}

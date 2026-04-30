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

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTernary(t *testing.T) {
	t.Run("returns true value when condition is true", func(t *testing.T) {
		result := Ternary(true, "yes", "no")
		assert.Equal(t, "yes", result)
	})

	t.Run("returns false value when condition is false", func(t *testing.T) {
		result := Ternary(false, "yes", "no")
		assert.Equal(t, "no", result)
	})

	t.Run("works with integers", func(t *testing.T) {
		result := Ternary(true, 42, 0)
		assert.Equal(t, 42, result)

		result = Ternary(false, 42, 0)
		assert.Equal(t, 0, result)
	})

	t.Run("works with pointers", func(t *testing.T) {
		truePtr := Ptr("true")
		falsePtr := Ptr("false")
		result := Ternary(true, truePtr, falsePtr)
		assert.Equal(t, truePtr, result)

		result = Ternary(false, truePtr, falsePtr)
		assert.Equal(t, falsePtr, result)
	})
}

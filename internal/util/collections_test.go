/*
 * © 2025 Snyk Limited
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

// TestSlicesEqualIgnoringOrder tests the SlicesEqualIgnoringOrder function
func TestSlicesEqualIgnoringOrder(t *testing.T) {
	t.Run("equal slices with same order", func(t *testing.T) {
		a := []string{"item1", "item2", "item3"}
		b := []string{"item1", "item2", "item3"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("equal slices with different order", func(t *testing.T) {
		a := []string{"item1", "item2", "item3"}
		b := []string{"item3", "item1", "item2"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("different length slices", func(t *testing.T) {
		a := []string{"item1", "item2"}
		b := []string{"item1", "item2", "item3"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("different content slices", func(t *testing.T) {
		a := []string{"item1", "item2"}
		b := []string{"item1", "item3"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("empty slices", func(t *testing.T) {
		a := []string{}
		b := []string{}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("one empty slice", func(t *testing.T) {
		a := []string{}
		b := []string{"item1"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("slices with duplicates", func(t *testing.T) {
		a := []string{"item1", "item1", "item2"}
		b := []string{"item1", "item2", "item1"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("slices with different duplicates", func(t *testing.T) {
		a := []string{"item1", "item1", "item2"}
		b := []string{"item1", "item2", "item2"}

		assert.False(t, SlicesEqualIgnoringOrder(a, b))
	})

	t.Run("works with strings", func(t *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"c", "a", "b"}

		assert.True(t, SlicesEqualIgnoringOrder(a, b))
	})
}

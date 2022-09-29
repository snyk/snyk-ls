/*
 * Copyright 2022 Snyk Ltd.
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

package concurrency

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicMap_ClearAll(t *testing.T) {
	atomicMap := AtomicMap{}
	atomicMap.Put("a", 1)
	atomicMap.Put("b", 2)

	atomicMap.ClearAll()

	assert.Equal(t, 0, atomicMap.Length())
}

func TestAtomicMap_Contains(t *testing.T) {
	atomicMap := AtomicMap{}
	atomicMap.Put("a", 1)

	assert.True(t, atomicMap.Contains("a"))
	assert.False(t, atomicMap.Contains("b"))
}

func TestAtomicMap_Delete(t *testing.T) {
	atomicMap := AtomicMap{}
	atomicMap.Put("a", 1)
	atomicMap.Put("b", 1)

	atomicMap.Delete("a")

	assert.False(t, atomicMap.Contains("a"))
	assert.True(t, atomicMap.Contains("b"))
	assert.Equal(t, 1, atomicMap.Length())
}

func TestAtomicMap_Get(t *testing.T) {
	atomicMap := AtomicMap{}
	atomicMap.Put("a", 1)

	assert.Equal(t, 1, atomicMap.Get("a"))
}

func TestAtomicMap_Length(t *testing.T) {
	atomicMap := AtomicMap{}

	atomicMap.Put("a", 1)

	assert.Equal(t, 1, atomicMap.Length())

	atomicMap.Delete("a")

	assert.Equal(t, 0, atomicMap.Length())
	atomicMap.Put("a", 1)
	atomicMap.Put("a", 2)
	atomicMap.Put("b", 3)

	assert.Equal(t, 2, atomicMap.Length())
}

func TestAtomicMap_Put(t *testing.T) {
	atomicMap := AtomicMap{}

	atomicMap.Put("a", 1)

	assert.Equal(t, 1, atomicMap.Get("a"))
	assert.True(t, atomicMap.Contains("a"))
	assert.Equal(t, 1, atomicMap.Length())

	atomicMap.Put("b", 1)

	assert.Equal(t, 1, atomicMap.Get("a"))
	assert.Equal(t, 1, atomicMap.Get("a"))
	assert.True(t, atomicMap.Contains("a"))
	assert.True(t, atomicMap.Contains("b"))
	assert.Equal(t, 2, atomicMap.Length())

	atomicMap.Put("b", 2)

	assert.Equal(t, 1, atomicMap.Get("a"))
	assert.Equal(t, 2, atomicMap.Get("b"))
	assert.True(t, atomicMap.Contains("a"))
	assert.True(t, atomicMap.Contains("b"))
	assert.Equal(t, 2, atomicMap.Length())

}

/*
 * © 2023 Snyk Limited All rights reserved.
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

package data_structure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_InsertionOrder(t *testing.T) {
	m := NewOrderedMap[string, string]()

	m.Add("a", "a")
	m.Add("b", "b")
	m.Add("c", "c")

	assert.Equal(t, []string{"a", "b", "c"}, m.Keys())
}

func Test_NonExistingKey(t *testing.T) {
	m := NewOrderedMap[string, string]()

	m.Add("a", "a")

	_, ok := m.Get("b")
	assert.False(t, ok)
}

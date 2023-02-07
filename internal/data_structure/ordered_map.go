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

type orderedMapEntry[K comparable, V any] struct {
	key   K
	value V
}

type OrderedMap[K comparable, V any] struct {
	m []orderedMapEntry[K, V]
}

func NewOrderedMap[K comparable, V any]() *OrderedMap[K, V] {
	return &OrderedMap[K, V]{
		m: make([]orderedMapEntry[K, V], 0),
	}
}

func (m *OrderedMap[K, V]) Add(key K, value V) {
	m.m = append(m.m, orderedMapEntry[K, V]{
		key:   key,
		value: value,
	})
}

func (m *OrderedMap[K, V]) Get(key K) (value V, ok bool) {
	for _, entry := range m.m {
		if entry.key == key {
			return entry.value, true
		}
	}

	return value, false
}

func (m *OrderedMap[K, V]) Keys() []K {
	keys := make([]K, 0)
	for _, entry := range m.m {
		keys = append(keys, entry.key)
	}
	return keys
}

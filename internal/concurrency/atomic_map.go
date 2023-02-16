/*
 * © 2022 Snyk Limited All rights reserved.
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
	"sync"
	"sync/atomic"
)

type AtomicMap struct {
	m      sync.Map
	length atomic.Value
	mut    sync.Mutex
}

func (m *AtomicMap) Get(key any) any {
	load, _ := m.m.Load(key)
	return load
}

func (m *AtomicMap) Contains(key any) bool {
	_, ok := m.m.Load(key)
	return ok
}

func (m *AtomicMap) Length() int {
	load := m.length.Load()
	if load == nil {
		return 0
	}
	return m.length.Load().(int)
}

func (m *AtomicMap) Put(key any, value any) {
	m.mut.Lock()
	if !m.Contains(key) {
		m.length.Store(m.Length() + 1)
	}
	m.m.Store(key, value)
	m.mut.Unlock()
}

func (m *AtomicMap) ClearAll() {
	m.mut.Lock()
	m.length.Store(0)
	m.m.Range(func(k any, _ any) bool {
		m.m.Delete(k)
		return true
	})
	m.mut.Unlock()
}

func (m *AtomicMap) Delete(key any) {
	m.mut.Lock()
	if m.Contains(key) {
		m.length.Store(m.length.Load().(int) - 1)
	}
	m.m.Delete(key)
	m.mut.Unlock()
}

func (m *AtomicMap) Range(f func(key any, value any) bool) {
	m.mut.Lock()
	m.m.Range(f)
	m.mut.Unlock()
}

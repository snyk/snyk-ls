/*
 * © 2024 Snyk Limited
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

package debounce

import (
	"sync"
	"time"
)

type Debouncer struct {
	mutex    sync.Mutex
	timeout  time.Duration
	timer    *time.Timer
	callback func()
}

func NewDebouncer(timeout time.Duration, callback func()) *Debouncer {
	return &Debouncer{
		timeout:  timeout,
		callback: callback,
	}
}

func (m *Debouncer) Debounce() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.timer == nil {
		m.timer = time.AfterFunc(m.timeout, m.callback)
		return
	}
	m.timer.Stop()
	m.timer.Reset(m.timeout)
}

func (m *Debouncer) UpdateDebounceCallback(callback func()) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.timer.Stop()
	m.timer = time.AfterFunc(m.timeout, callback)
}

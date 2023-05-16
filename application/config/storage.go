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

import "github.com/snyk/go-application-framework/pkg/configuration"

type StorageCallbackFunc func(string, any)

type StorageWithCallbacks interface {
	configuration.Storage
	RegisterCallback(key string, callback StorageCallbackFunc)
	UnRegisterCallback(key string)
}

type storage struct {
	data      map[string]any
	callbacks map[string]StorageCallbackFunc
}

type storageOption func(*storage)

func (s *storage) Set(key string, value any) error {
	callback := s.callbacks[key]
	s.data[key] = value

	if callback != nil {
		callback(key, value)
	}
	return nil
}

func NewStorage(opts ...storageOption) StorageWithCallbacks {
	s := &storage{
		data:      make(map[string]any),
		callbacks: make(map[string]StorageCallbackFunc),
	}

	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *storage) RegisterCallback(key string, callback StorageCallbackFunc) {
	s.callbacks[key] = callback
}

func (s *storage) UnRegisterCallback(key string) {
	s.callbacks[key] = nil
}

func WithCallbacks(callbacks map[string]StorageCallbackFunc) func(*storage) {
	return func(s *storage) {
		s.callbacks = callbacks
	}
}

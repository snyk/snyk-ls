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
	"time"

	"github.com/adrg/xdg"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type StorageCallbackFunc func(string, any)

type StorageWithCallbacks interface {
	configuration.Storage
	RegisterCallback(key string, callback StorageCallbackFunc)
	UnRegisterCallback(key string)
}

type storage struct {
	callbacks   map[string]StorageCallbackFunc
	jsonStorage *configuration.JsonStorage
}

func (s *storage) Refresh(config configuration.Configuration, key string) error {
	return s.jsonStorage.Refresh(config, key)
}

func (s *storage) Lock(ctx context.Context, retryDelay time.Duration) error {
	return s.jsonStorage.Lock(ctx, retryDelay)
}

func (s *storage) Unlock() error {
	return s.jsonStorage.Unlock()
}

type storageOption func(*storage)

func (s *storage) Set(key string, value any) error {
	callback := s.callbacks[key]

	if callback != nil {
		callback(key, value)
	}

	err := s.jsonStorage.Set(key, value)
	if err != nil {
		return err
	}
	return nil
}

func NewStorageWithCallbacks(opts ...storageOption) (StorageWithCallbacks, error) {
	// we ignore the error and just work without locking
	file, err := xdg.ConfigFile("snyk/ls-config")
	if err != nil {
		return nil, err
	}

	s := &storage{
		callbacks:   make(map[string]StorageCallbackFunc),
		jsonStorage: configuration.NewJsonStorage(file),
	}

	for _, opt := range opts {
		opt(s)
	}
	return s, err
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

func WithStorageFile(file string) func(*storage) {
	return func(s *storage) {
		s.jsonStorage = configuration.NewJsonStorage(file)
	}
}

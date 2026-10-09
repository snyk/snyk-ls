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

// Package storage implements the framework storage interface for configuration
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type StorageCallbackFunc func(string, any)

type StorageWithCallbacks interface {
	configuration.Storage
	RegisterCallback(key string, callback StorageCallbackFunc)
	UnRegisterCallback(key string)
	KeysByPrefix(prefix string) ([]string, error)
	WatchFileForWritesByOtherProcesses(ctx context.Context, interval time.Duration)
}

type storage struct {
	callbacks                map[string]StorageCallbackFunc
	jsonStorage              *configuration.JsonStorage
	storageFile              string
	mutex                    sync.RWMutex
	logger                   *zerolog.Logger
	valuesKnownToThisProcess map[string]any
}

func (s *storage) Refresh(config configuration.Configuration, key string) error {
	s.mutex.Lock()

	contents, err := os.ReadFile(s.storageFile)
	if err != nil {
		s.mutex.Unlock()
		return err
	}
	doc := map[string]interface{}{}
	err = json.Unmarshal(contents, &doc)
	if err != nil {
		s.mutex.Unlock()
		return err
	}

	value, ok := doc[key]
	if ok {
		s.valuesKnownToThisProcess[key] = value
	}
	s.mutex.Unlock()
	if ok {
		config.Set(key, value)
	}
	return nil
}

func (s *storage) WatchFileForWritesByOtherProcesses(ctx context.Context, interval time.Duration) {
	s.rememberCurrentValues()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runCallbacksForWritesByOtherProcesses()
			}
		}
	}()
}

func (s *storage) rememberCurrentValues() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if doc, err := s.readFile(); err == nil {
		for key := range s.callbacks {
			if value, ok := doc[key]; ok {
				s.valuesKnownToThisProcess[key] = value
			}
		}
	}
}

func (s *storage) runCallbacksForWritesByOtherProcesses() {
	type change struct {
		callback StorageCallbackFunc
		key      string
		value    any
	}
	var changes []change

	s.mutex.Lock()
	doc, err := s.readFile()
	if err != nil {
		s.mutex.Unlock()
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Debug().Err(err).Msg("could not read storage file to detect external changes")
		}
		return
	}

	for key, callback := range s.callbacks {
		value, ok := doc[key]
		if callback == nil || !ok || reflect.DeepEqual(value, s.valuesKnownToThisProcess[key]) {
			continue
		}
		s.valuesKnownToThisProcess[key] = value
		changes = append(changes, change{callback: callback, key: key, value: value})
	}
	s.mutex.Unlock()

	for _, c := range changes {
		s.logger.Debug().Str("key", c.key).Msg("storage key changed by another process")
		c.callback(c.key, c.value)
	}
}

func (s *storage) readFile() (map[string]any, error) {
	contents, err := os.ReadFile(s.storageFile)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	err = json.Unmarshal(contents, &doc)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func asJsonValue(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var decoded any
	if json.Unmarshal(encoded, &decoded) != nil {
		return value
	}
	return decoded
}

// KeysByPrefix reads the storage file and returns all keys matching the given prefix.
func (s *storage) KeysByPrefix(prefix string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	contents, err := os.ReadFile(s.storageFile)
	if err != nil {
		return nil, err
	}
	doc := map[string]interface{}{}
	err = json.Unmarshal(contents, &doc)
	if err != nil {
		return nil, err
	}

	var keys []string
	for key := range doc {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (s *storage) Lock(ctx context.Context, retryDelay time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.jsonStorage.Lock(ctx, retryDelay)
}

func (s *storage) Unlock() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.jsonStorage.Unlock()
}

type storageOption func(*storage)

func (s *storage) Set(key string, value any) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.jsonStorage.Set(key, value)
	if err != nil {
		s.logger.Err(err).Msgf("error writing %s to configuration file %s", key, s.storageFile)
	}

	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) {
		err = os.WriteFile(s.storageFile, []byte("{}"), 0o666)
		if err != nil {
			return err
		}
		err = s.jsonStorage.Set(key, value)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	s.valuesKnownToThisProcess[key] = asJsonValue(value)

	callback := s.callbacks[key]
	if callback != nil {
		callback(key, value)
	}

	return err
}

func NewStorageWithCallbacks(opts ...storageOption) (StorageWithCallbacks, error) {
	// we ignore the error and just work without locking
	file, err := xdg.ConfigFile("snyk/ls-config")
	if err != nil {
		return nil, err
	}

	nop := zerolog.Nop()
	s := &storage{
		callbacks:                make(map[string]StorageCallbackFunc),
		jsonStorage:              configuration.NewJsonStorage(file),
		logger:                   &nop,
		storageFile:              file,
		valuesKnownToThisProcess: make(map[string]any),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(s.storageFile), 0o755); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *storage) RegisterCallback(key string, callback StorageCallbackFunc) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.callbacks[key] = callback
}

func (s *storage) UnRegisterCallback(key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
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
		s.storageFile = file
	}
}

func WithLogger(logger *zerolog.Logger) func(*storage) {
	return func(s *storage) {
		l := logger.With().Str("component", "storageWithCallbacks").Logger()
		s.logger = &l
	}
}

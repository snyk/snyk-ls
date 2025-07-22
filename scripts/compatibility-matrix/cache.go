/*
 * © 2024 Snyk Limited All rights reserved.
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

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache provides filesystem-based caching for API responses
type Cache struct {
	basePath string
}

// NewCache creates a new cache instance
func NewCache(basePath string) *Cache {
	return &Cache{basePath: basePath}
}

// CacheEntry represents a cached item with metadata
type CacheEntry struct {
	Data      interface{}   `json:"data"`
	Timestamp time.Time     `json:"timestamp"`
	TTL       time.Duration `json:"ttl"`
}

// Get retrieves a cached value
func (c *Cache) Get(key string, result interface{}) (bool, error) {
	path := c.getPath(key)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return false, err
	}

	// Check if cache is expired
	if time.Since(entry.Timestamp) > entry.TTL {
		return false, nil
	}

	// Unmarshal the actual data
	dataBytes, err := json.Marshal(entry.Data)
	if err != nil {
		return false, err
	}

	return true, json.Unmarshal(dataBytes, result)
}

// Set stores a value in the cache
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) error {
	entry := CacheEntry{
		Data:      value,
		Timestamp: time.Now(),
		TTL:       ttl,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}

	path := c.getPath(key)

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// getPath returns the filesystem path for a cache key
func (c *Cache) getPath(key string) string {
	// Create a safe filename from the key
	hash := sha256.Sum256([]byte(key))
	filename := hex.EncodeToString(hash[:]) + ".json"

	// Use first 2 chars of hash for directory sharding
	return filepath.Join(c.basePath, filename[:2], filename)
}

// Clear removes all cached data
func (c *Cache) Clear() error {
	return os.RemoveAll(c.basePath)
}

// GetCLIVersionCacheKey generates a cache key for CLI version lookups
func GetCLIVersionCacheKey(protocolVersion string) string {
	return fmt.Sprintf("cli-version-preview-%s", protocolVersion)
}

// GetReleaseCacheKey generates a cache key for release data
func GetReleaseCacheKey(repo string, tag string) string {
	return fmt.Sprintf("release-%s-%s", repo, tag)
}

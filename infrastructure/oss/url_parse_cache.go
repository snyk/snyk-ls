/*
 * © 2025-2026 Snyk Limited
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

package oss

import (
	"net/url"
	"sync"
)

const maxParsedURLStringCacheEntries = 4096

// parsedURLStringCache stores one *url.URL per distinct raw URL string while keeping
// a hard cap so long-lived language-server sessions do not retain every unique URL.
var parsedURLStringCache = newBoundedURLParseCache(maxParsedURLStringCacheEntries)

type boundedURLParseCache struct {
	mu     sync.RWMutex
	max    int
	values map[string]*url.URL
}

func newBoundedURLParseCache(limit int) *boundedURLParseCache {
	return &boundedURLParseCache{
		max:    limit,
		values: make(map[string]*url.URL),
	}
}

func (c *boundedURLParseCache) loadCopy(raw string) (*url.URL, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	orig, ok := c.values[raw]
	if !ok {
		return nil, false
	}
	copied := *orig
	return &copied, true
}

func (c *boundedURLParseCache) storeCopy(raw string, parsed *url.URL) *url.URL {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.values[raw]; ok {
		copied := *existing
		return &copied
	}
	if len(c.values) < c.max {
		c.values[raw] = parsed
	}
	copied := *parsed
	return &copied
}

func (c *boundedURLParseCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.values)
}

func (c *boundedURLParseCache) resetForTests() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values = make(map[string]*url.URL)
}

// urlParseCachedCopy parses raw once per distinct string and returns a shallow copy of *url.URL
// so each consumer keeps an independent pointer (same semantics as calling url.Parse every time).
func urlParseCachedCopy(raw string) (*url.URL, error) {
	if cached, ok := parsedURLStringCache.loadCopy(raw); ok {
		return cached, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	return parsedURLStringCache.storeCopy(raw, u), nil
}

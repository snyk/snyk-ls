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

// parsedURLStringCache stores one *url.URL per distinct raw URL string (megaproject-scale
// OSS scans repeat the same advisory links across many findings).
var parsedURLStringCache sync.Map // string -> *url.URL (canonical parsed value; not mutated after store)

// urlParseCachedCopy parses raw once per distinct string and returns a shallow copy of *url.URL
// so each consumer keeps an independent pointer (same semantics as calling url.Parse every time).
func urlParseCachedCopy(raw string) (*url.URL, error) {
	if v, ok := parsedURLStringCache.Load(raw); ok {
		orig, ok := v.(*url.URL)
		if ok {
			c := *orig
			return &c, nil
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	parsedURLStringCache.Store(raw, u)
	c := *u
	return &c, nil
}

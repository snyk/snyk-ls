/*
 * © 2026 Snyk Limited
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

package backend

import (
	"time"

	"github.com/erni27/imcache"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

// MemoryBackend is the cp11r.3 default: the same imcache semantics IssueCache
// used before the StorageBackend abstraction existed.
type MemoryBackend struct {
	c *imcache.Cache[types.FilePath, []types.Issue]
}

var _ StorageBackend = (*MemoryBackend)(nil)

// NewMemoryBackend wraps an existing imcache instance. IssueCache owns the
// lifecycle; callers must not replace the imcache without going through
// IssueCache.SetCacheForTests.
func NewMemoryBackend(c *imcache.Cache[types.FilePath, []types.Issue]) *MemoryBackend {
	return &MemoryBackend{c: c}
}

// NewDefaultMemoryBackend creates an imcache with the same default expiration
// policy as issuecache.NewIssueCache used historically (12h default TTL).
func NewDefaultMemoryBackend() *MemoryBackend {
	c := imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Hour * 12),
	)
	return NewMemoryBackend(c)
}

// Imcache returns the underlying shard. Exposed for production code paths that
// still need the concrete type (e.g. tests replacing the cache) and will
// shrink as callers move to StorageBackend-only APIs.
func (m *MemoryBackend) Imcache() *imcache.Cache[types.FilePath, []types.Issue] {
	return m.c
}

func (m *MemoryBackend) RemoveExpired() {
	m.c.RemoveExpired()
}

func (m *MemoryBackend) Get(path types.FilePath) ([]types.Issue, bool) {
	return m.c.Get(path)
}

func (m *MemoryBackend) Set(path types.FilePath, issues []types.Issue) {
	m.c.Set(path, issues, imcache.WithDefaultExpiration())
}

func (m *MemoryBackend) GetAll() snyk.IssuesByFile {
	return m.c.GetAll()
}

func (m *MemoryBackend) Remove(path types.FilePath) {
	m.c.Remove(path)
}

func (m *MemoryBackend) ForEachPath(fn func(path types.FilePath) bool) {
	for p := range m.c.GetAll() {
		if !fn(p) {
			return
		}
	}
}

func (m *MemoryBackend) Close() error {
	return nil
}

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

package issuecache

import (
	"strings"

	"github.com/erni27/imcache"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/issuecache/backend"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// NewIssueCacheForProduct returns an IssueCache whose StorageBackend is chosen
// from types.SettingIssueCacheBackend ("bolt" default, or "memory" / "disk").
// On bolt open failure it logs and falls back to memory so the LS stays usable.
func NewIssueCacheForProduct(engine workflow.Engine, p product.Product) *IssueCache {
	conf := engine.GetConfiguration()
	mode := strings.ToLower(strings.TrimSpace(types.GetGlobalString(conf, types.SettingIssueCacheBackend)))
	if mode == "" {
		mode = "memory"
	}
	switch mode {
	case "bolt", "disk":
		cacheDir := persistence.CacheDir(conf)
		db, err := backend.OpenBoltDBForCacheDir(cacheDir)
		if err != nil {
			engine.GetLogger().Warn().Err(err).Str("product", string(p)).Msg("issue cache bolt backend unavailable; using memory")
			return NewIssueCache(p)
		}
		bb := backend.NewBoltBackend(db, p)
		return NewIssueCacheWithStorage(p, bb, nil)
	default:
		return NewIssueCache(p)
	}
}

// NewIssueCacheWithStorage constructs an IssueCache with an explicit backend.
// im is non-nil only for MemoryBackend; bolt-backed caches leave it nil.
func NewIssueCacheWithStorage(p product.Product, store backend.StorageBackend, im *imcache.Cache[types.FilePath, []types.Issue]) *IssueCache {
	return &IssueCache{
		product: p,
		store:   store,
		Cache:   im,
		index:   NewIssueIndex(),
		side:    newCodeActionsSide(),
	}
}

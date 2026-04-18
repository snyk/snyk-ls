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
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/issuecache/backend"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// forEachBackend runs fn twice: default memory IssueCache, then bolt-backed
// IssueCache (IDE-1940 cp11r.9 parity matrix).
func forEachBackend(t *testing.T, p product.Product, fn func(t *testing.T, c *IssueCache)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		fn(t, NewIssueCache(p))
	})
	t.Run("bolt", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingIssueCacheBackend), "bolt")
		c := NewIssueCacheForProduct(engine, p)
		t.Cleanup(func() { _ = backend.CloseBoltDBForTesting(persistence.CacheDir(conf)) })
		fn(t, c)
	})
}

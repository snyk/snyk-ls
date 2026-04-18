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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/issuecache/backend"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestNewIssueCacheForProduct_memoryDefault(t *testing.T) {
	engine := testutil.UnitTest(t)
	c := NewIssueCacheForProduct(engine, product.ProductCode)
	require.NotNil(t, c)
	require.NotNil(t, c.Cache)
}

func TestNewIssueCacheForProduct_bolt(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueCacheBackend), "bolt")

	c := NewIssueCacheForProduct(engine, product.ProductCode)
	require.NotNil(t, c)
	assert.Nil(t, c.Cache)
	t.Cleanup(func() { _ = backend.CloseBoltDBForTesting(persistence.CacheDir(conf)) })

	path := types.FilePath("/a/b.go")
	c.AddToCache([]types.Issue{&snyk.Issue{
		ID:               "r",
		AffectedFilePath: path,
		AdditionalData:   snyk.CodeIssueData{Key: "k"},
	}})
	got := c.IssuesForFile(path)
	require.Len(t, got, 1)
}

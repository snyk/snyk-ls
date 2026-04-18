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
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// These tests assert that the in-memory IssueIndex stays consistent with the
// rich-payload cache across every mutation entry point on IssueCache. They are
// the safety net for cp11r.2 (IDE-1940): later checkpoints will let the index
// survive a backend swap, so any divergence caught here would silently corrupt
// the disk backend once it lands.

func collectIndexKeys(t *testing.T, c *IssueCache) map[string]types.FilePath {
	t.Helper()
	paths := c.Index().Paths()
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	out := make(map[string]types.FilePath)
	for _, p := range paths {
		for _, k := range c.Index().KeysForPath(p) {
			out[k] = p
		}
	}
	return out
}

func TestIssueCache_AddToCacheKeepsIndexInSync(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		actionID := uuid.New()
		issue := buildIssue(t, "k1", "a.go", actionID)

		c.AddToCache([]types.Issue{issue})

		assert.Equal(t, 1, c.Index().Len())
		entry, ok := c.Index().EntryByKey("k1")
		require.True(t, ok)
		assert.Equal(t, types.FilePath("a.go"), entry.Path)
		assert.Equal(t, []uuid.UUID{actionID}, entry.CodeActionUUIDs)
		owner, ok := c.Index().KeyForActionUUID(actionID)
		require.True(t, ok)
		assert.Equal(t, "k1", owner)
	})
}

func TestIssueCache_AddToCacheDeduplicatesIndex(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		first := buildIssue(t, "same-key", "a.go")
		second := buildIssue(t, "same-key", "a.go")

		c.AddToCache([]types.Issue{first})
		c.AddToCache([]types.Issue{second})

		assert.Equal(t, 1, c.Index().Len())
		assert.Equal(t, []string{"same-key"}, c.Index().KeysForPath("a.go"))
		assert.Len(t, c.IssuesForFile("a.go"), 1)
	})
}

func TestIssueCache_ClearIssuesEvictsIndexEntries(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		c.AddToCache([]types.Issue{
			buildIssue(t, "k1", "a.go"),
			buildIssue(t, "k2", "a.go"),
			buildIssue(t, "k3", "b.go"),
		})

		c.ClearIssues("a.go")

		keys := collectIndexKeys(t, c)
		assert.Equal(t, map[string]types.FilePath{"k3": "b.go"}, keys)
		assert.Empty(t, c.IssuesForFile("a.go"))
	})
}

func TestIssueCache_ClearIssuesByPathEvictsIndexRecursively(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		c.AddToCache([]types.Issue{
			buildIssue(t, "k1", "/root/a.go"),
			buildIssue(t, "k2", "/root/sub/b.go"),
			buildIssue(t, "k3", "/other/c.go"),
		})

		c.ClearIssuesByPath("/root")

		keys := collectIndexKeys(t, c)
		assert.Equal(t, map[string]types.FilePath{"k3": "/other/c.go"}, keys)
	})
}

func TestIssueCache_ClearByIssueSliceEvictsIndex(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		survivor := buildIssue(t, "k-survive", "keep.go")
		victim := buildIssue(t, "k-victim", "drop.go")
		c.AddToCache([]types.Issue{survivor, victim})

		c.ClearByIssueSlice([]types.Issue{victim})

		keys := collectIndexKeys(t, c)
		assert.Equal(t, map[string]types.FilePath{"k-survive": "keep.go"}, keys)
	})
}

func TestIssueCache_RemoveFromCacheEvictsIndex(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		c.AddToCache([]types.Issue{
			buildIssue(t, "k1", "a.go"),
			buildIssue(t, "k2", "b.go"),
		})

		c.RemoveFromCache(map[types.FilePath]bool{"a.go": true})

		keys := collectIndexKeys(t, c)
		assert.Equal(t, map[string]types.FilePath{"k2": "b.go"}, keys)
	})
}

func TestIssueCache_ClearResetsIndex(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		c.AddToCache([]types.Issue{
			buildIssue(t, "k1", "a.go", uuid.New()),
			buildIssue(t, "k2", "b.go", uuid.New()),
		})

		c.Clear()

		assert.Equal(t, 0, c.Index().Len())
		assert.Empty(t, c.Index().Paths())
	})
}

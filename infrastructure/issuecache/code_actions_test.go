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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestIssueCache_CodeActionsSurviveReadAfterStrip(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		id := uuid.New()
		issue := buildIssue(t, "k1", "a.go", id)

		c.AddToCache([]types.Issue{issue})

		stored := c.IssuesForFile("a.go")
		require.Len(t, stored, 1)
		assert.Len(t, stored[0].GetCodeActions(), 1)
		assert.Equal(t, id, *stored[0].GetCodeActions()[0].GetUuid())
	})
}

func TestIssueCache_CodeActionsEvictedOnClearOtherPath(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		id := uuid.New()
		c.AddToCache([]types.Issue{
			buildIssue(t, "k1", "a.go", id),
			buildIssue(t, "k2", "b.go", uuid.New()),
		})

		c.ClearIssues("b.go")

		aIssues := c.IssuesForFile("a.go")
		require.Len(t, aIssues, 1)
		assert.Len(t, aIssues[0].GetCodeActions(), 1)

		assert.Empty(t, c.IssuesForFile("b.go"))
	})
}

func TestIssueCache_CodeActionsGoneAfterClear(t *testing.T) {
	forEachBackend(t, product.ProductCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		c.AddToCache([]types.Issue{buildIssue(t, "k1", "a.go", uuid.New())})

		c.Clear()

		assert.Empty(t, c.IssuesForFile("a.go"))
		_, ok := c.side.actionsForKey("k1")
		assert.False(t, ok)
	})
}

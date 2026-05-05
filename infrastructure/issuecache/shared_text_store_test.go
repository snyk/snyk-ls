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
	"sync"
	"testing"
	"time"

	"github.com/erni27/imcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

func buildOssIssueWithSharedText(key string, path types.FilePath, description string) *snyk.Issue {
	return &snyk.Issue{
		ID:               "SNYK-JS-SHARED-1",
		AffectedFilePath: path,
		Product:          product.ProductOpenSource,
		FormattedMessage: "formatted: " + description,
		Message:          "message: " + description,
		AdditionalData: snyk.OssIssueData{
			Key:         key,
			Title:       "OSS title",
			Description: description,
			Remediation: "remediate: " + description,
			CvssSources: []types.CvssSource{{
				Type:             "primary",
				Vector:           "CVSS:3.1/shared",
				Assigner:         "Snyk",
				Severity:         "high",
				CvssVersion:      "3.1",
				ModificationTime: "2026-05-05T00:00:00Z",
			}},
			References: []types.Reference{{Title: "reference: " + description}},
		},
	}
}

func buildIacIssueWithSharedText(key string, path types.FilePath, publicID string, issueText string) *snyk.Issue {
	return &snyk.Issue{
		ID:               publicID,
		AffectedFilePath: path,
		Product:          product.ProductInfrastructureAsCode,
		FormattedMessage: "formatted: " + issueText,
		Message:          issueText,
		AdditionalData: snyk.IaCIssueData{
			Key:        key,
			Title:      "IaC title",
			PublicId:   publicID,
			Issue:      issueText,
			Impact:     "impact: " + issueText,
			Resolve:    "resolve: " + issueText,
			References: []string{"reference: " + issueText},
		},
	}
}

func TestIssueCache_SharedTextDeduplicatesOssPayloadsAndPrunesWhenUnreferenced(t *testing.T) {
	forEachBackend(t, product.ProductOpenSource, func(t *testing.T, c *IssueCache) {
		t.Helper()
		pathA := types.FilePath("/workspace/a/package.json")
		pathB := types.FilePath("/workspace/b/package.json")
		description := "large duplicated vulnerability description"

		c.AddToCache([]types.Issue{
			buildOssIssueWithSharedText("oss-a", pathA, description),
			buildOssIssueWithSharedText("oss-b", pathB, description),
		})

		assert.Less(t, c.sharedTextEntryCount(), 12, "duplicate OSS text fields should be interned instead of stored per issue")
		a := c.Issue("oss-a")
		require.NotNil(t, a)
		aData := a.GetAdditionalData().(snyk.OssIssueData)
		assert.Equal(t, description, aData.Description)
		assert.Equal(t, "formatted: "+description, a.GetFormattedMessage())

		c.ClearIssues(pathA)
		assert.NotZero(t, c.sharedTextEntryCount(), "text referenced by the second issue must stay alive")
		c.ClearIssues(pathB)
		assert.Zero(t, c.sharedTextEntryCount(), "shared text with no remaining issue references must be pruned")
	})
}

func TestIssueCache_SharedTextPrunesWhenMemoryTTLExpiresFinalIssue(t *testing.T) {
	c := NewIssueCache(product.ProductOpenSource)
	c.SetCacheForTests(imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Microsecond),
	))
	path := types.FilePath("/workspace/a/package.json")

	c.AddToCache([]types.Issue{
		buildOssIssueWithSharedText("oss-expiring", path, "large expiring vulnerability description"),
	})
	require.NotZero(t, c.sharedTextEntryCount(), "precondition: shared text should be interned before TTL expiry")

	time.Sleep(time.Millisecond)
	c.AddToCache(nil)

	assert.Zero(t, c.sharedTextEntryCount(), "shared text must be pruned when the final memory-backed issue expires")
}

func TestIssueCache_SharedTextPrunesWhenMemoryTTLExpiresOnRead(t *testing.T) {
	c := NewIssueCache(product.ProductOpenSource)
	c.SetCacheForTests(imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Microsecond),
	))
	path := types.FilePath("/workspace/a/package.json")

	c.AddToCache([]types.Issue{
		buildOssIssueWithSharedText("oss-expiring-read", path, "large read-expiring vulnerability description"),
	})
	require.NotZero(t, c.sharedTextEntryCount(), "precondition: shared text should be interned before TTL expiry")

	time.Sleep(time.Millisecond)
	require.Nil(t, c.Issue("oss-expiring-read"))

	assert.Zero(t, c.sharedTextEntryCount(), "shared text must be pruned when a read observes the final memory-backed issue expired")
	assert.Empty(t, c.CachedPaths(), "expired memory-backed paths should be removed from the owner index")
}

func TestIssueCache_SharedTextPrunesWhenMemoryTTLExpiresOnCachedPaths(t *testing.T) {
	c := NewIssueCache(product.ProductOpenSource)
	c.SetCacheForTests(imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Microsecond),
	))
	path := types.FilePath("/workspace/a/package.json")

	c.AddToCache([]types.Issue{
		buildOssIssueWithSharedText("oss-expiring-paths", path, "large cached-paths-expiring vulnerability description"),
	})
	require.NotZero(t, c.sharedTextEntryCount(), "precondition: shared text should be interned before TTL expiry")

	time.Sleep(time.Millisecond)

	assert.Empty(t, c.CachedPaths(), "expired memory-backed paths should be removed before returning cached paths")
	assert.Zero(t, c.sharedTextEntryCount(), "shared text must be pruned when CachedPaths observes memory TTL expiry")
}

func TestIssueCache_SharedTextPrunesWhenMemoryTTLExpiresOnIssuesSnapshot(t *testing.T) {
	c := NewIssueCache(product.ProductOpenSource)
	c.SetCacheForTests(imcache.New[types.FilePath, []types.Issue](
		imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Microsecond),
	))
	path := types.FilePath("/workspace/a/package.json")

	c.AddToCache([]types.Issue{
		buildOssIssueWithSharedText("oss-expiring-snapshot", path, "large snapshot-expiring vulnerability description"),
	})
	require.NotZero(t, c.sharedTextEntryCount(), "precondition: shared text should be interned before TTL expiry")

	time.Sleep(time.Millisecond)
	require.Empty(t, c.Issues())

	assert.Zero(t, c.sharedTextEntryCount(), "shared text must be pruned when Issues observes the final memory-backed issue expired")
	assert.Empty(t, c.CachedPaths(), "expired memory-backed paths should be removed from the owner index")
}

func TestIssueCache_SharedTextConcurrentMemoryReadsDoNotMutateInternedOssIssue(t *testing.T) {
	c := NewIssueCache(product.ProductOpenSource)
	path := types.FilePath("/workspace/concurrent/package.json")
	description := "large concurrently read vulnerability description"

	c.AddToCache([]types.Issue{
		buildOssIssueWithSharedText("oss-concurrent-read", path, description),
	})
	require.NotZero(t, c.sharedTextEntryCount(), "precondition: shared text should be interned before concurrent reads")

	const goroutines = 16
	const iterations = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				issue := c.Issue("oss-concurrent-read")
				require.NotNil(t, issue)
				data := issue.GetAdditionalData().(snyk.OssIssueData)
				assert.Equal(t, description, data.Description)
			}
		}()
	}
	wg.Wait()
}

func TestIssueCache_SharedTextDeduplicatesIacPayloadsAndPrunesOnPathClear(t *testing.T) {
	forEachBackend(t, product.ProductInfrastructureAsCode, func(t *testing.T, c *IssueCache) {
		t.Helper()
		path := types.FilePath("/workspace/main.tf")
		issueText := "security group allows public ingress"

		c.AddToCache([]types.Issue{
			buildIacIssueWithSharedText("iac-a", path, "SNYK-CC-TF-1", issueText),
			buildIacIssueWithSharedText("iac-b", path, "SNYK-CC-TF-1", issueText),
		})

		assert.Less(t, c.sharedTextEntryCount(), 10, "duplicate IaC text fields should be interned instead of stored per issue")
		loaded := c.IssuesForFile(path)
		require.Len(t, loaded, 2)
		iacData := loaded[0].GetAdditionalData().(snyk.IaCIssueData)
		assert.Equal(t, issueText, iacData.Issue)
		assert.Equal(t, "impact: "+issueText, iacData.Impact)
		assert.Equal(t, "resolve: "+issueText, iacData.Resolve)

		c.ClearIssues(path)
		assert.Zero(t, c.sharedTextEntryCount(), "all IaC shared text should be pruned after clearing the only path")
	})
}

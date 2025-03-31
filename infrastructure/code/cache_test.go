/*
 * © 2024 Snyk Limited
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

package code

import (
	"context"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	"github.com/erni27/imcache"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type MockScanner struct {
	mock.Mock
}

func (m *MockScanner) Scan(ctx context.Context, path types.FilePath, folderPath types.FilePath, options interface{}) ([]types.Issue, error) {
	args := m.Called(ctx, path, folderPath, options)
	return args.Get(0).([]types.Issue), args.Error(1)
}

func (m *MockScanner) Issue(key string) *snyk.Issue {
	args := m.Called(key)
	return args.Get(0).(*snyk.Issue)
}
func TestScanner_Cache(t *testing.T) {
	t.Run("should add issues to the cache", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		scanner.addToCache([]types.Issue{&snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java"}})
		scanner.addToCache([]types.Issue{&snyk.Issue{ID: "issue2", AffectedFilePath: "file2.java"}})

		_, added := scanner.issueCache.Get("file1.java")
		require.True(t, added)
		_, added = scanner.issueCache.Get("file2.java")
		require.True(t, added)
	})
	t.Run("should automatically expire entries after a time", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		scanner.issueCache = imcache.New[types.FilePath, []types.Issue](
			imcache.WithDefaultExpirationOption[types.FilePath, []types.Issue](time.Microsecond),
		)
		issue := &snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java"}
		scanner.addToCache([]types.Issue{issue})

		time.Sleep(time.Millisecond)
		_, found := scanner.issueCache.Get("file1.java")
		require.False(t, found)
	})
	t.Run("should add scan results to cache", func(t *testing.T) {
		//_, scanner := setupTestScanner(t)
		// preload cache with one issue
		//scanner.issueCache.RemoveAll()
		//scanner.issueCache.Set(
		//	"file2.java",
		//	[]types.Issue{&snyk.Issue{ID: "issue2", AdditionalData: snyk.CodeIssueData{Key: uuid.New().String()}}},
		//	imcache.WithDefaultExpiration(),
		//)
		filePath, folderPath := TempWorkdirWithIssues(t)

		mockScanner := new(MockScanner)
		mockScanner.On("Scan", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return([]types.Issue{FakeIssue}, nil)
		mockScanner.On("Issue", FakeIssue.AdditionalData.GetKey()).Return(FakeIssue)

		// now scan
		_, err := mockScanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		// new issue from scan should have been added
		issue := mockScanner.Issue(FakeIssue.AdditionalData.GetKey())
		require.NotNil(t, issue)
	})
	t.Run("should removeFromCache previous scan results for files to be scanned from cache", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		evictionChan := make(chan types.FilePath)
		scanner.issueCache = imcache.New[types.FilePath, []types.Issue](imcache.WithEvictionCallbackOption(func(key types.FilePath, value []types.Issue, reason imcache.EvictionReason) {
			go func() {
				evictionChan <- key
			}()
		}))
		scanner.issueCache.Set("file2.java", []types.Issue{&snyk.Issue{ID: "issue2"}}, imcache.WithDefaultExpiration())
		filePath, folderPath := TempWorkdirWithIssues(t)

		// first scan should add issues to the cache
		_, err := scanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		// second scan should evict the previous results from the cache
		results, err := scanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		for i := 0; i < len(results); i++ {
			select {
			case key := <-evictionChan:
				scanner.C.Logger().Debug().Msg(string("evicted from cache" + key))
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for eviction")
			}
		}
	})
	t.Run("should call given eviction handlers", func(t *testing.T) {
		// BL should work like this
		// cache is initialized with an eviction handler
		// eviction handler should call a function that iterates over additional handlers
		_, scanner := setupTestScanner(t)
		evictionChan := make(chan types.FilePath)
		testEvictionHandler := func(path types.FilePath) {
			go func() { evictionChan <- path }()
		}
		filePath, folderPath := TempWorkdirWithIssues(t)
		scanner.RegisterCacheRemovalHandler(testEvictionHandler)
		scanner.issueCache.Set(filePath, []types.Issue{&snyk.Issue{ID: "issue2"}}, imcache.WithDefaultExpiration())

		// first scan should add issues to the cache
		_, err := scanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		// second scan should evict the previous results from the cache
		results, err := scanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		for i := 0; i < len(results); i++ {
			select {
			case path := <-evictionChan:
				scanner.C.Logger().Debug().Msg(string("evicted from cache" + path))
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for eviction")
			}
		}
	})
	t.Run("clear issues should evict all issues", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		evictionChan := make(chan types.FilePath)
		testEvictionHandler := func(path types.FilePath) {
			go func() { evictionChan <- path }()
		}
		scanner.RegisterCacheRemovalHandler(testEvictionHandler)
		filePath, folderPath := TempWorkdirWithIssues(t)
		scanner.issueCache.Set(filePath, []types.Issue{&snyk.Issue{ID: "issue2"}}, imcache.WithDefaultExpiration())

		// first scan should add issues to the cache
		results, err := scanner.Scan(context.Background(), filePath, folderPath, nil)
		require.NoError(t, err)

		// now we clear the cache
		scanner.ClearIssues(filePath)

		for i := 0; i < len(results); i++ {
			select {
			case path := <-evictionChan:
				scanner.C.Logger().Debug().Msg(string("evicted from cache" + path))
			case <-time.After(time.Second):
				t.Fatal("timeout waiting for eviction")
			}
		}
	})
	t.Run("should de-duplicate issues", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		scanner.issueCache.RemoveAll()
		issue1 := &snyk.Issue{ID: "issue1", AffectedFilePath: "file2.java", AdditionalData: snyk.CodeIssueData{Key: "1"}}
		issue2 := &snyk.Issue{ID: "issue2", AffectedFilePath: "file2.java", AdditionalData: snyk.CodeIssueData{Key: "2"}}
		issue3 := &snyk.Issue{ID: "issue3", AffectedFilePath: "file2.java", AdditionalData: snyk.CodeIssueData{Key: "3"}}

		issues := []types.Issue{issue1, issue2, issue3}

		scanner.addToCache(issues)
		scanner.addToCache(issues)

		require.Len(t, scanner.IssuesForFile("file2.java"), len(issues))
	})
}

func TestScanner_IssueProvider(t *testing.T) {
	t.Run("should find issue by key", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := &snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]types.Issue{issue})

		foundIssue := scanner.Issue("key")
		require.Equal(t, issue, foundIssue)
	})

	t.Run("should find issue by path and range", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := &snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]types.Issue{issue})

		foundIssues := scanner.IssuesForRange("file1.java", issue.Range)

		require.Contains(t, foundIssues, issue)
	})
	t.Run("should not find issue by path when range does not overlap", func(t *testing.T) {
		_, scanner := setupTestScanner(t)
		issue := &snyk.Issue{ID: "issue1", AffectedFilePath: "file1.java", AdditionalData: &snyk.CodeIssueData{Key: "key"}}
		scanner.addToCache([]types.Issue{issue})

		foundIssues := scanner.IssuesForRange(
			"file1.java",
			types.Range{
				Start: types.Position{Line: 3},
				End:   types.Position{Line: 4},
			},
		)
		require.NotContains(t, foundIssues, issue)
	})
}

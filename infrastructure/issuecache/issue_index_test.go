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
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// buildIssue is a minimal fake Issue constructor for the index tests. We rely on
// the real *snyk.Issue type because the index calls the getter methods of the
// types.Issue interface; a bare mock would not exercise the real projection.
func buildIssue(t *testing.T, key string, path types.FilePath, actionIDs ...uuid.UUID) *snyk.Issue {
	t.Helper()
	issue := &snyk.Issue{
		ID:               "rule-" + key,
		Severity:         types.High,
		IssueType:        types.CodeSecurityVulnerability,
		AffectedFilePath: path,
		Product:          product.ProductCode,
		Fingerprint:      "fp-" + key,
		GlobalIdentity:   "gid-" + key,
		Range: types.Range{
			Start: types.Position{Line: 1, Character: 2},
			End:   types.Position{Line: 1, Character: 5},
		},
		AdditionalData: snyk.CodeIssueData{Key: key, Title: "t-" + key},
	}
	for _, id := range actionIDs {
		boundID := id
		issue.CodeActions = append(issue.CodeActions, &snyk.CodeAction{Uuid: &boundID})
	}
	return issue
}

func TestIssueIndex_UpsertPopulatesAllLookupTables(t *testing.T) {
	idx := NewIssueIndex()
	actionID := uuid.New()
	issue := buildIssue(t, "issue-1", "a.go", actionID)

	idx.UpsertFromIssue(issue)

	require.Equal(t, 1, idx.Len())

	entry, ok := idx.EntryByKey("issue-1")
	require.True(t, ok)
	assert.Equal(t, "issue-1", entry.Key)
	assert.Equal(t, types.FilePath("a.go"), entry.Path)
	assert.Equal(t, types.High, entry.Severity)
	assert.Equal(t, product.ProductCode, entry.Product)
	assert.Equal(t, "fp-issue-1", entry.Fingerprint)
	assert.Equal(t, "gid-issue-1", entry.GlobalIdentity)
	assert.Equal(t, []uuid.UUID{actionID}, entry.CodeActionUUIDs)

	keys := idx.KeysForPath("a.go")
	assert.Equal(t, []string{"issue-1"}, keys)

	owner, ok := idx.KeyForActionUUID(actionID)
	require.True(t, ok)
	assert.Equal(t, "issue-1", owner)

	paths := idx.Paths()
	assert.Equal(t, []types.FilePath{"a.go"}, paths)
}

func TestIssueIndex_UpsertReplacesPriorEntryAndUpdatesCrossReferences(t *testing.T) {
	idx := NewIssueIndex()
	oldAction := uuid.New()
	newAction := uuid.New()

	first := buildIssue(t, "k", "old/path.go", oldAction)
	idx.UpsertFromIssue(first)

	// Same key, new path + new action UUID. The old cross-references must disappear.
	second := buildIssue(t, "k", "new/path.go", newAction)
	idx.UpsertFromIssue(second)

	require.Equal(t, 1, idx.Len())
	assert.Empty(t, idx.KeysForPath("old/path.go"))
	assert.Equal(t, []string{"k"}, idx.KeysForPath("new/path.go"))

	_, ok := idx.KeyForActionUUID(oldAction)
	assert.False(t, ok, "old action UUID must be evicted")

	owner, ok := idx.KeyForActionUUID(newAction)
	require.True(t, ok)
	assert.Equal(t, "k", owner)
}

func TestIssueIndex_RemoveByKey(t *testing.T) {
	idx := NewIssueIndex()
	action := uuid.New()
	idx.UpsertFromIssue(buildIssue(t, "k", "a.go", action))

	idx.RemoveByKey("k")

	_, ok := idx.EntryByKey("k")
	assert.False(t, ok)
	assert.Empty(t, idx.KeysForPath("a.go"))
	_, ok = idx.KeyForActionUUID(action)
	assert.False(t, ok)
	assert.Equal(t, 0, idx.Len())
}

func TestIssueIndex_RemoveByPathEvictsAllEntriesOnThatPath(t *testing.T) {
	idx := NewIssueIndex()
	a1 := uuid.New()
	a2 := uuid.New()
	a3 := uuid.New()

	idx.UpsertFromIssue(buildIssue(t, "k1", "same.go", a1))
	idx.UpsertFromIssue(buildIssue(t, "k2", "same.go", a2))
	idx.UpsertFromIssue(buildIssue(t, "k3", "other.go", a3))

	require.Equal(t, 3, idx.Len())

	idx.RemoveByPath("same.go")

	require.Equal(t, 1, idx.Len())
	_, ok := idx.EntryByKey("k1")
	assert.False(t, ok)
	_, ok = idx.EntryByKey("k2")
	assert.False(t, ok)
	entry, ok := idx.EntryByKey("k3")
	require.True(t, ok)
	assert.Equal(t, types.FilePath("other.go"), entry.Path)

	assert.Empty(t, idx.KeysForPath("same.go"))
	assert.Equal(t, []string{"k3"}, idx.KeysForPath("other.go"))

	_, ok = idx.KeyForActionUUID(a1)
	assert.False(t, ok)
	_, ok = idx.KeyForActionUUID(a2)
	assert.False(t, ok)
	owner, ok := idx.KeyForActionUUID(a3)
	require.True(t, ok)
	assert.Equal(t, "k3", owner)
}

func TestIssueIndex_ClearEmptiesEverything(t *testing.T) {
	idx := NewIssueIndex()
	idx.UpsertFromIssue(buildIssue(t, "k1", "a.go", uuid.New()))
	idx.UpsertFromIssue(buildIssue(t, "k2", "b.go"))

	idx.Clear()

	assert.Equal(t, 0, idx.Len())
	assert.Empty(t, idx.Paths())
	assert.Empty(t, idx.KeysForPath("a.go"))
}

func TestIssueIndex_NilIssueIsIgnored(t *testing.T) {
	idx := NewIssueIndex()
	idx.UpsertFromIssue(nil)
	assert.Equal(t, 0, idx.Len())
}

func TestIssueIndex_PathsReturnsAllIndexedFiles(t *testing.T) {
	idx := NewIssueIndex()
	idx.UpsertFromIssue(buildIssue(t, "k1", "a.go"))
	idx.UpsertFromIssue(buildIssue(t, "k2", "b.go"))
	idx.UpsertFromIssue(buildIssue(t, "k3", "a.go"))

	paths := idx.Paths()
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	assert.Equal(t, []types.FilePath{"a.go", "b.go"}, paths)
}

func TestIssueIndex_ConcurrentMutationsAreSafe(t *testing.T) {
	idx := NewIssueIndex()

	const workers = 16
	const perWorker = 64

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := "w" + uuidLikeString(w, i)
				path := types.FilePath("file-" + uuidLikeString(w%4, 0) + ".go")
				idx.UpsertFromIssue(buildIssue(t, key, path))
				idx.EntryByKey(key)
				idx.KeysForPath(path)
			}
		}(w)
	}
	wg.Wait()

	assert.Equal(t, workers*perWorker, idx.Len())
}

// uuidLikeString produces a deterministic, cheap key without pulling in strconv.Itoa
// for every iteration of the concurrency test.
func uuidLikeString(a, b int) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[a&0xf], hex[(a>>4)&0xf], '-', hex[b&0xf], hex[(b>>4)&0xf], hex[(b>>8)&0xf], hex[(b>>12)&0xf]})
}

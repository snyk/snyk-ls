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
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// buildIssueB mirrors buildIssue in issue_index_test.go but accepts *testing.B.
// Keeping the allocator identical to the test path so test-time regressions are
// visible in bench-time heap numbers too.
func buildIssueB(key string, path types.FilePath, actionIDs ...uuid.UUID) *snyk.Issue {
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
		bound := id
		issue.CodeActions = append(issue.CodeActions, &snyk.CodeAction{Uuid: &bound})
	}
	return issue
}

// indexBenchScales is the set of N used by cp11r regression gates. The smallest
// values keep `make benchmark` cheap; the largest represents a megaproject-class
// workload (see IDE-1940_implementation_plan.md Checkpoint 20).
var indexBenchScales = []int{100, 1_000, 10_000, 80_000}

func seedIndex(n int) (*IssueIndex, []*snyk.Issue, []uuid.UUID) {
	idx := NewIssueIndex()
	issues := make([]*snyk.Issue, n)
	uuids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		uuids[i] = uuid.New()
		path := types.FilePath("file_" + strconv.Itoa(i%500) + ".go")
		issues[i] = buildIssueB("k-"+strconv.Itoa(i), path, uuids[i])
		idx.UpsertFromIssue(issues[i])
	}
	return idx, issues, uuids
}

func BenchmarkIssueIndex_UpsertFromIssue(b *testing.B) {
	for _, n := range indexBenchScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			issues := make([]*snyk.Issue, n)
			for i := 0; i < n; i++ {
				path := types.FilePath("file_" + strconv.Itoa(i%500) + ".go")
				issues[i] = buildIssueB("k-"+strconv.Itoa(i), path, uuid.New())
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				idx := NewIssueIndex()
				for _, issue := range issues {
					idx.UpsertFromIssue(issue)
				}
				_ = idx
			}
			b.ReportMetric(float64(n), "issues/op")
		})
	}
}

func BenchmarkIssueIndex_EntryByKey(b *testing.B) {
	for _, n := range indexBenchScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			idx, issues, _ := seedIndex(n)
			targetKey := issues[n/2].GetAdditionalData().GetKey()
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				_, _ = idx.EntryByKey(targetKey)
			}
		})
	}
}

func BenchmarkIssueIndex_KeyForActionUUID(b *testing.B) {
	for _, n := range indexBenchScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			idx, _, uuids := seedIndex(n)
			target := uuids[n/2]
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				_, _ = idx.KeyForActionUUID(target)
			}
		})
	}
}

func BenchmarkIssueIndex_KeysForPath(b *testing.B) {
	for _, n := range indexBenchScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			idx, _, _ := seedIndex(n)
			targetPath := types.FilePath("file_" + strconv.Itoa((n/2)%500) + ".go")
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				_ = idx.KeysForPath(targetPath)
			}
		})
	}
}

func BenchmarkIssueIndex_RemoveByPath(b *testing.B) {
	// RemoveByPath is amortized O(keys-on-path). The same-path density is the
	// cost axis; benchmark the common "many issues on one file" shape.
	for _, n := range indexBenchScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			issues := make([]*snyk.Issue, n)
			path := types.FilePath("hot.go")
			for i := 0; i < n; i++ {
				issues[i] = buildIssueB("k-"+strconv.Itoa(i), path)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				idx := NewIssueIndex()
				for _, issue := range issues {
					idx.UpsertFromIssue(issue)
				}
				idx.RemoveByPath(path)
			}
		})
	}
}

// BenchmarkIssueIndex_ConcurrentReadHeavy reflects the megaproject post-publish
// pattern: many LSP read callbacks racing on a mostly-static index. Regressions
// here would mean the RWMutex became a contention point and the hot code lens /
// hover paths would queue up.
func BenchmarkIssueIndex_ConcurrentReadHeavy(b *testing.B) {
	const n = 10_000
	idx, issues, uuids := seedIndex(n)

	var mixIdx atomic.Uint64
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(mixIdx.Add(1)) % n
			_, _ = idx.EntryByKey(issues[i].GetAdditionalData().GetKey())
			_, _ = idx.KeyForActionUUID(uuids[i])
			_ = idx.KeysForPath(issues[i].GetAffectedFilePath())
		}
	})
}

// BenchmarkIssueIndex_MixedWriteReadContention mirrors the ingest pattern: one
// producer is upserting while N-1 consumers read. Meant to catch a regression
// where the lock is held across an O(N) remove path and starves readers.
func BenchmarkIssueIndex_MixedWriteReadContention(b *testing.B) {
	const initial = 10_000
	idx, issues, _ := seedIndex(initial)

	const writers = 1
	const readers = 7
	stop := make(chan struct{})
	var readOps atomic.Uint64
	var wg sync.WaitGroup

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					key := issues[int(readOps.Add(1))%initial].GetAdditionalData().GetKey()
					_, _ = idx.EntryByKey(key)
				}
			}
		}()
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		for j := 0; j < writers; j++ {
			path := types.FilePath("file_" + strconv.Itoa(i%500) + ".go")
			idx.UpsertFromIssue(buildIssueB("write-"+strconv.Itoa(i), path))
		}
	}
	close(stop)
	wg.Wait()
	b.ReportMetric(float64(readOps.Load())/float64(b.Elapsed().Seconds()+1e-9), "reads/s")
}

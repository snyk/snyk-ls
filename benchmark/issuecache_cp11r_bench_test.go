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

package benchmark

import (
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// The cp11r benchmark gate suite exists to catch performance regressions in the
// IssueCache hot paths that the file-indexed cache introduces (IDE-1940 cp11r).
// Every new benchmark is parameterised on a realistic megaproject-class scale
// so an asymptotic regression (e.g. an accidental O(N) in what should be O(1))
// shows up as the N grows.
//
// Scale selection:
//
//	1_000   - small project (one medium scan)
//	10_000  - large project (a busy monorepo)
//	80_000  - megaproject 500-code + 500-OSS post-publish peak (see cp20 heap
//	          samples in IDE-1940_implementation_plan.md)
//
// These do not replace the real scan benchmark (Test_SmokeRealScanMonorepoFixture,
// see benchmark/README.md); they are fast gates that can run in CI without a
// live Snyk API token and without BENCHMARK_REAL_SCAN_MONOREPO=1.
var cp11rIssueCacheScales = []int{1_000, 10_000, 80_000}

type cp11rCorpus struct {
	issues  []types.Issue
	uuids   []uuid.UUID
	midKey  string
	midPath types.FilePath
	midUUID uuid.UUID
}

// newCp11rCorpus builds a reproducible issue corpus that spreads N issues over
// ~500 files (mirrors the generated monorepo fixture). One code action is
// attached to each issue so the action-UUID lookup has something to find.
func newCp11rCorpus(n int) cp11rCorpus {
	issues := make([]types.Issue, n)
	uuids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		uuids[i] = uuid.UUID{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		bound := uuids[i]
		path := types.FilePath("/workspace/monorepo/leaf_" + strconv.Itoa(i%500) + "/file.ts")
		issues[i] = &snyk.Issue{
			ID:               "rule-" + strconv.Itoa(i%37),
			Severity:         types.High,
			IssueType:        types.CodeSecurityVulnerability,
			AffectedFilePath: path,
			Product:          product.ProductCode,
			Fingerprint:      "fp-" + strconv.Itoa(i),
			GlobalIdentity:   "gid-" + strconv.Itoa(i),
			Range: types.Range{
				Start: types.Position{Line: i % 500, Character: 1},
				End:   types.Position{Line: i % 500, Character: 10},
			},
			AdditionalData: snyk.CodeIssueData{Key: "issue-" + strconv.Itoa(i), Title: "t"},
			CodeActions: []types.CodeAction{
				&snyk.CodeAction{Uuid: &bound},
			},
		}
	}
	mid := n / 2
	return cp11rCorpus{
		issues:  issues,
		uuids:   uuids,
		midKey:  issues[mid].GetAdditionalData().GetKey(),
		midPath: issues[mid].GetAffectedFilePath(),
		midUUID: uuids[mid],
	}
}

// reportNsPerIssue normalises a per-op cost that iterated over N issues to a
// per-issue cost so scale comparisons ("did we keep O(N)?") are immediate.
func reportNsPerIssue(b *testing.B, n int) {
	b.Helper()
	if n <= 0 {
		return
	}
	nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	b.ReportMetric(nsPerOp/float64(n), "ns/issue")
}

func BenchmarkCp11r_IssueCache_AddToCache(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				cache := issuecache.NewIssueCache(product.ProductCode)
				cache.AddToCache(corpus.issues)
			}
			reportNsPerIssue(b, n)
		})
	}
}

func BenchmarkCp11r_IssueCache_IssuesForFile(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			cache := issuecache.NewIssueCache(product.ProductCode)
			cache.AddToCache(corpus.issues)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				_ = cache.IssuesForFile(corpus.midPath)
			}
		})
	}
}

// BenchmarkCp11r_IssueCache_IssueByKey is the primary asymptotic gate. Today's
// IssueCache.Issue(key) walks every cached entry. cp11r.3+ will serve this
// lookup from the index in O(1). The bench curve across N is the evidence.
func BenchmarkCp11r_IssueCache_IssueByKey(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			cache := issuecache.NewIssueCache(product.ProductCode)
			cache.AddToCache(corpus.issues)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				_ = cache.Issue(corpus.midKey)
			}
		})
	}
}

// BenchmarkCp11r_IssueCache_IssueByActionUUID models the fixCodeIssue path
// after cp11r.6 lands: resolve an issue from a code-action UUID via the index.
// For now we compose it from public APIs (Index().KeyForActionUUID + Issue())
// so the bench is stable across the upcoming refactor.
func BenchmarkCp11r_IssueCache_IssueByActionUUID(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			cache := issuecache.NewIssueCache(product.ProductCode)
			cache.AddToCache(corpus.issues)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				key, ok := cache.Index().KeyForActionUUID(corpus.midUUID)
				if !ok {
					b.Fatalf("action UUID %s not indexed", corpus.midUUID)
				}
				_ = cache.Issue(key)
			}
		})
	}
}

// BenchmarkCp11r_IssueCache_Issues gates the full-map snapshot cost. cp11r.7
// switches this to a lazy iterator on the disk backend; the memory backend
// should stay close to today's number.
func BenchmarkCp11r_IssueCache_Issues(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			cache := issuecache.NewIssueCache(product.ProductCode)
			cache.AddToCache(corpus.issues)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				m := cache.Issues()
				runtime.KeepAlive(m)
			}
		})
	}
}

func BenchmarkCp11r_IssueCache_Clear(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				cache := issuecache.NewIssueCache(product.ProductCode)
				cache.AddToCache(corpus.issues)
				cache.Clear()
			}
		})
	}
}

// BenchmarkCp11r_IssueCache_ClearIssuesByPath exercises the recursive folder
// walk. The (folder,product) replace transaction in cp11r.4 calls this under
// the hood; a regression would translate into a proportional post-scan stall.
func BenchmarkCp11r_IssueCache_ClearIssuesByPath(b *testing.B) {
	for _, n := range cp11rIssueCacheScales {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			corpus := newCp11rCorpus(n)
			b.ResetTimer()
			b.ReportAllocs()
			for b.Loop() {
				cache := issuecache.NewIssueCache(product.ProductCode)
				cache.AddToCache(corpus.issues)
				cache.ClearIssuesByPath("/workspace/monorepo")
			}
		})
	}
}

// BenchmarkCp11r_IssueCache_ParallelDidOpen models the post-publish "many IDE
// tabs suddenly opened" burst: N readers hit IssuesForFile concurrently on a
// static cache. Output reads/s comes from b.ReportMetric.
func BenchmarkCp11r_IssueCache_ParallelDidOpen(b *testing.B) {
	const n = 10_000
	corpus := newCp11rCorpus(n)
	cache := issuecache.NewIssueCache(product.ProductCode)
	cache.AddToCache(corpus.issues)

	var counter atomic.Uint64
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			path := corpus.issues[int(counter.Add(1))%n].GetAffectedFilePath()
			_ = cache.IssuesForFile(path)
		}
	})
}

// BenchmarkCp11r_IssueCache_IngestWhileReading is a canary for the "did the
// index lock become a scan bottleneck?" question. One writer streams issues in
// while readers pound the index. The measured op is the writer ingest loop.
func BenchmarkCp11r_IssueCache_IngestWhileReading(b *testing.B) {
	const primed = 5_000
	primedCorpus := newCp11rCorpus(primed)
	cache := issuecache.NewIssueCache(product.ProductCode)
	cache.AddToCache(primedCorpus.issues)

	const readers = 4
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
					path := primedCorpus.issues[int(readOps.Add(1))%primed].GetAffectedFilePath()
					_ = cache.IssuesForFile(path)
				}
			}
		}()
	}

	// Smaller per-op write batches keep ns/op reading comparable across scales.
	const writeBatch = 256
	writeCorpus := newCp11rCorpus(writeBatch)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		cache.AddToCache(writeCorpus.issues)
	}
	close(stop)
	wg.Wait()

	elapsed := b.Elapsed().Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(readOps.Load())/elapsed, "reads/s")
	}
}

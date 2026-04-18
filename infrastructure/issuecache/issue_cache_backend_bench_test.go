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
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/issuecache/backend"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// prodBenchScales matches the historical cp11r gate (1k / 10k / 80k issues).
var prodBenchScales = []int{1_000, 10_000, 80_000}

// prodBenchCorpus is N issues spread across ~500 paths with one code action each
// (same shape as the former benchmark/newCp11rCorpus).
type prodBenchCorpus struct {
	issues  []types.Issue
	uuids   []uuid.UUID
	midKey  string
	midPath types.FilePath
	midUUID uuid.UUID
}

func newProdBenchCorpus(n int) prodBenchCorpus {
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
	return prodBenchCorpus{
		issues:  issues,
		uuids:   uuids,
		midKey:  issues[mid].GetAdditionalData().GetKey(),
		midPath: issues[mid].GetAffectedFilePath(),
		midUUID: uuids[mid],
	}
}

func reportNsPerIssueProd(b *testing.B, n int) {
	b.Helper()
	if n <= 0 {
		return
	}
	nsPerOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	b.ReportMetric(nsPerOp/float64(n), "ns/issue")
}

// newProdLikeIssueCache returns one IssueCache backed like production: memory uses
// a single imcache shard; bolt uses one OpenBoltDBForCacheDir handle for the lifetime
// of the benchmark subtest (not a new DB per iteration).
func newProdLikeIssueCache(b *testing.B, useBolt bool) *IssueCache {
	b.Helper()
	if !useBolt {
		return NewIssueCache(product.ProductCode)
	}
	dir := b.TempDir()
	db, err := backend.OpenBoltDBForCacheDir(dir)
	if err != nil {
		b.Fatalf("open bolt: %v", err)
	}
	bb := backend.NewBoltBackend(db, product.ProductCode)
	c := NewIssueCacheWithStorage(product.ProductCode, bb, nil)
	b.Cleanup(func() { _ = backend.CloseBoltDBForTesting(dir) })
	return c
}

type prodBackendMode struct {
	name string
	bolt bool
}

func prodBackendModes() []prodBackendMode {
	return []prodBackendMode{
		{name: "memory", bolt: false},
		{name: "bolt", bolt: true},
	}
}

func benchIssueCacheProdPrimed(b *testing.B, fn func(b *testing.B, c *IssueCache, corpus prodBenchCorpus)) {
	b.Helper()
	for _, mode := range prodBackendModes() {
		for _, n := range prodBenchScales {
			b.Run(fmt.Sprintf("%s/N=%d", mode.name, n), func(b *testing.B) {
				corpus := newProdBenchCorpus(n)
				c := newProdLikeIssueCache(b, mode.bolt)
				c.AddToCache(corpus.issues)
				b.ResetTimer()
				b.ReportAllocs()
				fn(b, c, corpus)
			})
		}
	}
}

// BenchmarkIssueCacheProd_IssuesForFile is a hot read path: single file, long-lived cache.
func BenchmarkIssueCacheProd_IssuesForFile(b *testing.B) {
	benchIssueCacheProdPrimed(b, func(b *testing.B, c *IssueCache, corpus prodBenchCorpus) {
		b.Helper()
		for b.Loop() {
			_ = c.IssuesForFile(corpus.midPath)
		}
	})
}

// BenchmarkIssueCacheProd_IssueByKey exercises Issue(key) on a primed cache (full scan today).
func BenchmarkIssueCacheProd_IssueByKey(b *testing.B) {
	benchIssueCacheProdPrimed(b, func(b *testing.B, c *IssueCache, corpus prodBenchCorpus) {
		b.Helper()
		for b.Loop() {
			_ = c.Issue(corpus.midKey)
		}
	})
}

// BenchmarkIssueCacheProd_IssueByActionUUID models fix flow: index UUID → Issue.
func BenchmarkIssueCacheProd_IssueByActionUUID(b *testing.B) {
	benchIssueCacheProdPrimed(b, func(b *testing.B, c *IssueCache, corpus prodBenchCorpus) {
		b.Helper()
		for b.Loop() {
			key, ok := c.Index().KeyForActionUUID(corpus.midUUID)
			if !ok {
				b.Fatalf("action UUID %s not indexed", corpus.midUUID)
			}
			_ = c.Issue(key)
		}
	})
}

// BenchmarkIssueCacheProd_Issues is the full snapshot path (Issues()).
func BenchmarkIssueCacheProd_Issues(b *testing.B) {
	benchIssueCacheProdPrimed(b, func(b *testing.B, c *IssueCache, corpus prodBenchCorpus) {
		b.Helper()
		for b.Loop() {
			m := c.Issues()
			runtime.KeepAlive(m)
		}
	})
}

// BenchmarkIssueCacheProd_ReplaceFolderScan models a folder-scoped rescan: clear under
// the workspace root then re-ingest the same corpus on one long-lived backend.
func BenchmarkIssueCacheProd_ReplaceFolderScan(b *testing.B) {
	const monorepoRoot = "/workspace/monorepo"
	for _, mode := range prodBackendModes() {
		for _, n := range prodBenchScales {
			b.Run(fmt.Sprintf("%s/N=%d", mode.name, n), func(b *testing.B) {
				corpus := newProdBenchCorpus(n)
				c := newProdLikeIssueCache(b, mode.bolt)
				c.AddToCache(corpus.issues)
				b.ResetTimer()
				b.ReportAllocs()
				for b.Loop() {
					c.ClearIssuesByPath(monorepoRoot)
					c.AddToCache(corpus.issues)
				}
				reportNsPerIssueProd(b, n)
			})
		}
	}
}

// BenchmarkIssueCacheProd_FullClearCycle models add-then-clear on a single backend.
func BenchmarkIssueCacheProd_FullClearCycle(b *testing.B) {
	for _, mode := range prodBackendModes() {
		for _, n := range prodBenchScales {
			b.Run(fmt.Sprintf("%s/N=%d", mode.name, n), func(b *testing.B) {
				corpus := newProdBenchCorpus(n)
				c := newProdLikeIssueCache(b, mode.bolt)
				b.ResetTimer()
				b.ReportAllocs()
				for b.Loop() {
					c.AddToCache(corpus.issues)
					c.Clear()
				}
				reportNsPerIssueProd(b, n)
			})
		}
	}
}

// BenchmarkIssueCacheProd_ParallelDidOpen is concurrent IssuesForFile on a static primed cache.
func BenchmarkIssueCacheProd_ParallelDidOpen(b *testing.B) {
	const n = 10_000
	corpus := newProdBenchCorpus(n)

	for _, mode := range prodBackendModes() {
		b.Run(mode.name, func(b *testing.B) {
			cache := newProdLikeIssueCache(b, mode.bolt)
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
		})
	}
}

// BenchmarkIssueCacheProd_IngestWhileReading is one writer streaming small batches while
// readers hit IssuesForFile on a long-lived cache (contention canary).
func BenchmarkIssueCacheProd_IngestWhileReading(b *testing.B) {
	const primed = 5_000
	primedCorpus := newProdBenchCorpus(primed)
	writeBatch := 256
	writeCorpus := newProdBenchCorpus(writeBatch)

	for _, mode := range prodBackendModes() {
		b.Run(mode.name, func(b *testing.B) {
			cache := newProdLikeIssueCache(b, mode.bolt)
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
		})
	}
}

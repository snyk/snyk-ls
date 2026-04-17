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
	"io/fs"
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

// Must match progress.ToServerProgressChannel capacity in internal/progress/progress.go.
const progressParamsChannelCap = 100_000

func benchFixtureScale() (codeDirs, ossDirs int) {
	if os.Getenv("BENCHMARK_FULL_FIXTURE") == "1" {
		return CodeFolderCount, OSSFolderCount
	}
	return 20, 20
}

func syntheticIssues(files, perFile int) []types.Issue {
	out := make([]types.Issue, 0, files*perFile)
	for f := range files {
		path := types.FilePath(fmt.Sprintf("/workspace/project/file_%d.ts", f))
		for i := range perFile {
			out = append(out, &snyk.Issue{
				AffectedFilePath: path,
				Product:          product.ProductCode,
				AdditionalData:   snyk.CodeIssueData{Key: fmt.Sprintf("issue-%d-%d", f, i)},
				Range:            types.Range{},
			})
		}
	}
	return out
}

func syntheticIssuesForGoroutine(g, files int) []types.Issue {
	out := make([]types.Issue, 0, files)
	for i := range files {
		path := types.FilePath(fmt.Sprintf("/workspace/g%d/file_%d.ts", g, i))
		out = append(out, &snyk.Issue{
			AffectedFilePath: path,
			Product:          product.ProductCode,
			AdditionalData:   snyk.CodeIssueData{Key: fmt.Sprintf("g%d-issue-%d", g, i)},
			Range:            types.Range{},
		})
	}
	return out
}

func BenchmarkGenerateMonorepoFixture(b *testing.B) {
	codeDirs, ossDirs := benchFixtureScale()
	b.ReportAllocs()
	for b.Loop() {
		root := b.TempDir()
		if err := generateMonorepoFixture(b, root, codeDirs, ossDirs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMonorepoWalk(b *testing.B) {
	root := b.TempDir()
	codeDirs, ossDirs := benchFixtureScale()
	if err := generateMonorepoFixture(b, root, codeDirs, ossDirs); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		var n int
		if err := WalkMonorepoFixture(root, func(_ string, _ fs.DirEntry) error {
			n++
			return nil
		}); err != nil {
			b.Fatal(err)
		}
		runtime.KeepAlive(n)
	}
}

func BenchmarkIssueCacheAddToCacheAndIssues(b *testing.B) {
	const files, perFile = 200, 10
	issues := syntheticIssues(files, perFile)
	b.ReportAllocs()
	for b.Loop() {
		cache := issuecache.NewIssueCache(product.ProductCode)
		cache.AddToCache(issues)
		_ = cache.Issues()
	}
}

func BenchmarkIssueCacheIssueLookup(b *testing.B) {
	const files, perFile = 200, 20
	issues := syntheticIssues(files, perFile)
	cache := issuecache.NewIssueCache(product.ProductCode)
	cache.AddToCache(issues)
	key := issues[len(issues)/2].GetAdditionalData().GetKey()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = cache.Issue(key)
	}
}

func BenchmarkIssueCacheClear(b *testing.B) {
	const files, perFile = 100, 10
	issues := syntheticIssues(files, perFile)
	b.ReportAllocs()
	for b.Loop() {
		cache := issuecache.NewIssueCache(product.ProductCode)
		cache.AddToCache(issues)
		cache.Clear()
	}
}

func BenchmarkIssueCacheIssues(b *testing.B) {
	const files, perFile = 500, 5
	issues := syntheticIssues(files, perFile)
	cache := issuecache.NewIssueCache(product.ProductCode)
	cache.AddToCache(issues)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = cache.Issues()
	}
}

func BenchmarkIssueCacheConcurrentAdd(b *testing.B) {
	const goroutines = 8
	const perGoroutine = 50
	b.ReportAllocs()
	for b.Loop() {
		cache := issuecache.NewIssueCache(product.ProductCode)
		var wg sync.WaitGroup
		for g := range goroutines {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				cache.AddToCache(syntheticIssuesForGoroutine(g, perGoroutine))
			}(g)
		}
		wg.Wait()
	}
}

func BenchmarkProgressChannelCapacity(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ch := make(chan types.ProgressParams, progressParamsChannelCap)
		runtime.KeepAlive(ch)
	}
}

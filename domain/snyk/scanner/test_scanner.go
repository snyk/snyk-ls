/*
 * © 2022-2024 Snyk Limited
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

package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"

	"github.com/google/uuid"
)

var (
	_ snyk.CacheProvider    = (*TestScanner)(nil)
	_ snyk.CachedIssuePaths = (*TestScanner)(nil)
)

type TestScanner struct {
	mutex sync.Mutex
	calls int
	// StubIssues is the slice Scan feeds into ProcessResults (seeded into per-product caches first).
	StubIssues    []types.Issue
	SendAnalytics bool

	oss     *issuecache.IssueCache
	code    *issuecache.IssueCache
	iac     *issuecache.IssueCache
	secrets *issuecache.IssueCache
}

func NewTestScanner() *TestScanner {
	s := &TestScanner{calls: 0, SendAnalytics: true}
	s.ensureCaches()
	return s
}

func (s *TestScanner) ensureCaches() {
	if s.oss != nil {
		return
	}
	s.oss = issuecache.NewIssueCache(product.ProductOpenSource)
	s.code = issuecache.NewIssueCache(product.ProductCode)
	s.iac = issuecache.NewIssueCache(product.ProductInfrastructureAsCode)
	s.secrets = issuecache.NewIssueCache(product.ProductSecrets)
	if s.StubIssues == nil {
		s.StubIssues = []types.Issue{}
	}
}

func (s *TestScanner) Init(_ context.Context) error { return nil }

func (s *TestScanner) IsEnabled() bool {
	return true
}

const TestProduct product.Product = "Test Product"

func (s *TestScanner) Product() product.Product {
	return TestProduct
}

func (s *TestScanner) cacheForProduct(p product.Product) *issuecache.IssueCache {
	switch p {
	case product.ProductOpenSource:
		return s.oss
	case product.ProductCode:
		return s.code
	case product.ProductInfrastructureAsCode:
		return s.iac
	case product.ProductSecrets:
		return s.secrets
	default:
		panic(fmt.Sprintf("test scanner: unsupported product %q", p))
	}
}

func (s *TestScanner) seedCachesFromIssues(issues []types.Issue) {
	batches := make(map[product.Product][]types.Issue)
	for _, iss := range issues {
		p := iss.GetProduct()
		batches[p] = append(batches[p], iss)
	}
	for p, batch := range batches {
		s.cacheForProduct(p).AddToCache(batch)
	}
}

// SeedIssueCaches writes issues into per-product issue caches (mirrors what production scanners do before ProcessResults).
// Tests that call Folder.ProcessResults directly must call this when they expect cached diagnostics.
func (s *TestScanner) SeedIssueCaches(issues []types.Issue) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.ensureCaches()
	s.seedCachesFromIssues(issues)
}

func (s *TestScanner) Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, ostActionFunc types.PostAction) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.ensureCaches()

	var folderPath types.FilePath
	if fc, ok := ctx2.FolderConfigFromContext(ctx); ok && fc != nil {
		folderPath = fc.FolderPath
	}

	s.seedCachesFromIssues(s.StubIssues)

	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            s.StubIssues,
		Duration:          1234,
		TimestampFinished: time.Now().UTC(),
		UpdateGlobalCache: true,
		SendAnalytics:     s.SendAnalytics,
		Path:              folderPath,
	}
	processResults(ctx, data)
	s.calls++
}

func (s *TestScanner) Calls() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}

func (s *TestScanner) AddTestIssue(issue *snyk.Issue) {
	s.ensureCaches()
	if issue.AdditionalData == nil {
		issue.AdditionalData = snyk.OssIssueData{
			Key: util.Result(uuid.NewUUID()).String(),
		}
		issue.Product = product.ProductOpenSource
	}
	s.StubIssues = append(s.StubIssues, issue)
}

func (s *TestScanner) Issue(key string) types.Issue {
	for _, c := range s.caches() {
		if iss := c.Issue(key); iss != nil && iss.GetID() != "" {
			return iss
		}
	}
	return nil
}

func (s *TestScanner) Issues() snyk.IssuesByFile {
	out := snyk.IssuesByFile{}
	for _, c := range s.caches() {
		for path, issues := range c.Issues() {
			out[path] = append(out[path], issues...)
		}
	}
	return out
}

func (s *TestScanner) IssuesForFile(path types.FilePath) []types.Issue {
	var merged []types.Issue
	for _, c := range s.caches() {
		merged = append(merged, c.IssuesForFile(path)...)
	}
	return merged
}

func (s *TestScanner) IssuesForRange(path types.FilePath, r types.Range) []types.Issue {
	var merged []types.Issue
	for _, c := range s.caches() {
		merged = append(merged, c.IssuesForRange(path, r)...)
	}
	return merged
}

func (s *TestScanner) CachedPaths() []types.FilePath {
	seen := make(map[types.FilePath]struct{})
	var out []types.FilePath
	for _, c := range s.caches() {
		for _, p := range c.CachedPaths() {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (s *TestScanner) IsProviderFor(issueType product.FilterableIssueType) bool {
	for _, c := range s.caches() {
		if c.IsProviderFor(issueType) {
			return true
		}
	}
	return false
}

func (s *TestScanner) Clear() {
	for _, c := range s.caches() {
		c.Clear()
	}
}

func (s *TestScanner) ClearIssues(path types.FilePath) {
	for _, c := range s.caches() {
		c.ClearIssues(path)
	}
}

func (s *TestScanner) RegisterCacheRemovalHandler(handler func(path types.FilePath)) {
	for _, c := range s.caches() {
		c.RegisterCacheRemovalHandler(handler)
	}
}

func (s *TestScanner) caches() []*issuecache.IssueCache {
	s.ensureCaches()
	return []*issuecache.IssueCache{s.oss, s.code, s.iac, s.secrets}
}

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
	"sync"
	"time"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/util"
)

type TestScanner struct {
	mutex         sync.Mutex
	calls         int
	Issues        []types.Issue
	SendAnalytics bool
}

func NewTestScanner() *TestScanner {
	return &TestScanner{
		calls:         0,
		Issues:        []types.Issue{},
		SendAnalytics: true,
	}
}

func (s *TestScanner) Init() error { return nil }

func (s *TestScanner) IsEnabled() bool {
	return true
}

const TestProduct product.Product = "Test Product"

func (s *TestScanner) Product() product.Product {
	return TestProduct
}

func (s *TestScanner) Scan(ctx context.Context, path types.FilePath, processResults types.ScanResultProcessor, folderPath types.FilePath) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	data := types.ScanData{
		Product:           product.ProductOpenSource,
		Issues:            s.Issues,
		DurationMs:        1234,
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
	if issue.AdditionalData == nil {
		issue.AdditionalData = snyk.CodeIssueData{
			Key: util.Result(uuid.NewUUID()).String(),
		}
		issue.Product = product.ProductCode
	}
	s.Issues = append(s.Issues, issue)
}

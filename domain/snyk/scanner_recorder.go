/*
 * © 2022 Snyk Limited All rights reserved.
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

package snyk

import (
	"context"
	"sync"

	"github.com/snyk/snyk-ls/internal/product"
)

type TestScanner struct {
	mutex  sync.Mutex
	calls  int
	Issues []Issue
}

func NewTestScanner() *TestScanner {
	return &TestScanner{
		calls:  0,
		Issues: []Issue{},
	}
}

func (s *TestScanner) IsEnabled() bool {
	return true
}

const TestProduct product.Product = "Test Product"

func (s *TestScanner) Product() product.Product {
	return TestProduct
}

func (s *TestScanner) Scan(
	_ context.Context,
	_ string,
	processResults ScanResultProcessor,
	_ string,
) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	processResults(product.ProductOpenSource, s.Issues)
	s.calls++
}

func (s *TestScanner) Calls() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.calls
}

func (s *TestScanner) AddTestIssue(issue Issue) {
	s.Issues = append(s.Issues, issue)
}

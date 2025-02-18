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

package scanner

import (
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

var _ ScanNotifier = &MockScanNotifier{}

type MockScanNotifier struct {
	inProgressCalls []types.FilePath
	successCalls    []types.FilePath
	errorCalls      []types.FilePath
}

func NewMockScanNotifier() *MockScanNotifier { return &MockScanNotifier{} }

func (m *MockScanNotifier) SendInProgress(folderPath types.FilePath) {
	m.inProgressCalls = append(m.inProgressCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccessForAllProducts(folderPath types.FilePath) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccess(_ product.Product, folderPath types.FilePath) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendError(product product.Product, folderPath types.FilePath, errorMessage string) {
	m.errorCalls = append(m.errorCalls, folderPath)
}

func (m *MockScanNotifier) InProgressCalls() []types.FilePath {
	return m.inProgressCalls
}

func (m *MockScanNotifier) SuccessCalls() []types.FilePath {
	return m.successCalls
}

func (m *MockScanNotifier) ErrorCalls() []types.FilePath {
	return m.errorCalls
}

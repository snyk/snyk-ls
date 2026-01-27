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
	inProgressCalls []*types.FolderConfig
	successCalls    []*types.FolderConfig
	errorCalls      []types.FilePath
}

func NewMockScanNotifier() *MockScanNotifier { return &MockScanNotifier{} }

func (m *MockScanNotifier) SendInProgress(folderConfig *types.FolderConfig) {
	m.inProgressCalls = append(m.inProgressCalls, folderConfig)
}

func (m *MockScanNotifier) SendSuccessForAllProducts(folderConfig *types.FolderConfig) {
	m.successCalls = append(m.successCalls, folderConfig)
}

func (m *MockScanNotifier) SendSuccess(_ product.Product, folderConfig *types.FolderConfig) {
	m.successCalls = append(m.successCalls, folderConfig)
}

func (m *MockScanNotifier) SendError(_ product.Product, folderPath types.FilePath, _ string) {
	m.errorCalls = append(m.errorCalls, folderPath)
}

func (m *MockScanNotifier) InProgressCalls() []*types.FolderConfig {
	return m.inProgressCalls
}

func (m *MockScanNotifier) SuccessCalls() []*types.FolderConfig {
	return m.successCalls
}

func (m *MockScanNotifier) ErrorCalls() []types.FilePath {
	return m.errorCalls
}

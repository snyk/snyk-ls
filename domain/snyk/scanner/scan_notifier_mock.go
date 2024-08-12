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
)

var _ ScanNotifier = &MockScanNotifier{}

type MockScanNotifier struct {
	inProgressCalls []string
	successCalls    []string
	errorCalls      []string
}

func NewMockScanNotifier() *MockScanNotifier { return &MockScanNotifier{} }

func (m *MockScanNotifier) SendInProgress(folderPath string) {
	m.inProgressCalls = append(m.inProgressCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccessForAllProducts(folderPath string) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccess(_ product.Product, folderPath string) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendError(_ product.Product, folderPath string, _ string) {
	m.errorCalls = append(m.errorCalls, folderPath)
}

func (m *MockScanNotifier) InProgressCalls() []string {
	return m.inProgressCalls
}

func (m *MockScanNotifier) SuccessCalls() []string {
	return m.successCalls
}

func (m *MockScanNotifier) ErrorCalls() []string {
	return m.errorCalls
}

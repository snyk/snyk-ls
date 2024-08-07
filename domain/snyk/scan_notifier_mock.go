package snyk

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

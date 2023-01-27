package notification

import (
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/product"
)

var _ snyk.ScanNotifier = &MockScanNotifier{}

type MockScanNotifier struct {
	inProgressCalls []string
	successCalls    []string
	errorCalls      []string
}

func NewMockScanNotifier() *MockScanNotifier { return &MockScanNotifier{} }

func (m *MockScanNotifier) SendInProgress(folderPath string) {
	m.inProgressCalls = append(m.inProgressCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccess(product product.Product, folderPath string, issues []snyk.Issue) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendError(product product.Product, folderPath string) {
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

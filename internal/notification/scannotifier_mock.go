package notification

var _ ScanNotifier = &MockScanNotifier{}

type MockScanNotifier struct {
	inProgressCalls []string
	successCalls    []string
	errorCalls      []string
}

func (m *MockScanNotifier) SendInProgress(folderPath string) {
	m.inProgressCalls = append(m.inProgressCalls, folderPath)
}

func (m *MockScanNotifier) SendSuccess(folderPath string) {
	m.successCalls = append(m.successCalls, folderPath)
}

func (m *MockScanNotifier) SendError(folderPath string) {
	m.errorCalls = append(m.errorCalls, folderPath)
}

func (m *MockScanNotifier) GetInProgressCalls() []string {
	return m.inProgressCalls
}

func (m *MockScanNotifier) GetSuccessCalls() []string {
	return m.successCalls
}

func (m *MockScanNotifier) GetErrorCalls() []string {
	return m.errorCalls
}

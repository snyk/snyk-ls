package notification_test

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/notification"
)

var _ notification.Notifier = &MockNotifier{}

type MockNotifier struct {
	sendShowMessageCounter     int
	sendCounter                int
	sendErrorCounter           int
	sendErrorDiagnosticCounter int
	receiveCounter             int
	createListenerCounter      int
	disposeListenerCounter     int
}

func (m *MockNotifier) SendShowMessage(messageType sglsp.MessageType, message string) {
	m.sendShowMessageCounter++
}

func (m *MockNotifier) Send(msg any) { m.sendCounter++ }

func (m *MockNotifier) SendError(err error) { m.sendErrorCounter++ }

func (m *MockNotifier) SendErrorDiagnostic(path string, err error) { m.sendErrorDiagnosticCounter++ }

func (m *MockNotifier) Receive() (payload any, stop bool) {
	m.receiveCounter++
	return nil, false
}

func (m *MockNotifier) CreateListener(callback func(params any)) { m.createListenerCounter++ }

func (m *MockNotifier) DisposeListener() { m.disposeListenerCounter++ }

func (m *MockNotifier) SendShowMessageCounter() int { return m.sendShowMessageCounter }

func (m *MockNotifier) SendCounter() int { return m.sendCounter }

func (m *MockNotifier) SendErrorCounter() int { return m.sendErrorCounter }

func (m *MockNotifier) SendErrorDiagnosticCounter() int { return m.sendErrorDiagnosticCounter }

func (m *MockNotifier) ReceiveCounter() int { return m.receiveCounter }

func (m *MockNotifier) CreateListenerCounter() int { return m.createListenerCounter }

func (m *MockNotifier) DisposeListenerCounter() int { return m.disposeListenerCounter }

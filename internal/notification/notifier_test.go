package notification_test

import (
	"fmt"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/uri"
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
	sentMessages               []any
}

func NewMockNotifier() *MockNotifier { return &MockNotifier{} }

func (m *MockNotifier) SendShowMessage(messageType sglsp.MessageType, message string) {
	m.sendShowMessageCounter++
	m.sentMessages = append(m.sentMessages, sglsp.ShowMessageParams{
		Type:    messageType,
		Message: message,
	})
}

func (m *MockNotifier) Send(msg any) {
	m.sendCounter++
	m.sentMessages = append(m.sentMessages, msg)
}

func (m *MockNotifier) SendError(err error) {
	m.sendErrorCounter++
	m.sentMessages = append(m.sentMessages, sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
}

func (m *MockNotifier) SendErrorDiagnostic(path string, err error) {
	m.sendErrorDiagnosticCounter++
	msg := lsp.PublishDiagnosticsParams{
		URI: uri.PathToUri(path),
		Diagnostics: []lsp.Diagnostic{{
			Range:           sglsp.Range{},
			Severity:        lsp.DiagnosticsSeverityWarning,
			Code:            "Snyk Error",
			CodeDescription: lsp.CodeDescription{Href: "https://snyk.io/user-hub"},
			Message:         err.Error(),
		}},
	}
	m.sentMessages = append(m.sentMessages, msg)
}

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

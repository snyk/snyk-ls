package notification

import (
	"fmt"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/uri"
)

var _ Notifier = &MockNotifier{}

type MockNotifier struct {
	sendShowMessageCounter     int
	sendCounter                int
	sendErrorCounter           int
	sendErrorDiagnosticCounter int
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

func (m *MockNotifier) GetSendShowMessageCounter() int { return m.sendShowMessageCounter }

func (m *MockNotifier) GetSendCounter() int { return m.sendCounter }

func (m *MockNotifier) GetSendErrorCounter() int { return m.sendErrorCounter }

func (m *MockNotifier) GetSendErrorDiagnosticCounter() int { return m.sendErrorDiagnosticCounter }

func (m *MockNotifier) GetSentMessages() []any { return m.sentMessages }

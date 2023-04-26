package notification

import (
	"fmt"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/uri"
)

func NewNotifier() notification.Notifier {
	return &notifierImpl{
		channel:     make(chan any, 100),
		stopChannel: make(chan any, 100),
	}
}

type notifierImpl struct {
	channel     chan any
	stopChannel chan any
}

func (n *notifierImpl) SendShowMessage(messageType sglsp.MessageType, message string) {
	n.channel <- sglsp.ShowMessageParams{Type: messageType, Message: message}
}

func (n *notifierImpl) Send(msg any) {
	n.channel <- msg
}

func (n *notifierImpl) SendError(err error) {
	n.Send(sglsp.ShowMessageParams{
		Type:    sglsp.MTError,
		Message: fmt.Sprintf("Snyk encountered an error: %v", err),
	})
}

func (n *notifierImpl) SendErrorDiagnostic(path string, err error) {
	n.Send(lsp.PublishDiagnosticsParams{
		URI: uri.PathToUri(path),
		Diagnostics: []lsp.Diagnostic{{
			Range:           sglsp.Range{},
			Severity:        lsp.DiagnosticsSeverityWarning,
			Code:            "Snyk Error",
			CodeDescription: lsp.CodeDescription{Href: "https://snyk.io/user-hub"},
			Message:         err.Error(),
		}},
	})
}

func (n *notifierImpl) Receive() (payload any, stop bool) {
	select {
	case payload = <-n.channel:
		return payload, false
	case <-n.stopChannel:
		return payload, true
	}
}

func (n *notifierImpl) CreateListener(callback func(params any)) {
	// cleanup stopchannel before starting
	for {
		select {
		case <-n.stopChannel:
			continue
		default:
			break
		}
		break
	}
	go func() {
		for {
			payload, stop := n.Receive()
			if stop {
				break
			}
			callback(payload)
		}
	}()
}

func (n *notifierImpl) DisposeListener() {
	n.stopChannel <- true
}

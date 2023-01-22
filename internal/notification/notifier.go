package notification

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/notification"
)

var _ notification.Notifier = &notifierImpl{}

func NewNotifier() notification.Notifier { return &notifierImpl{} }

type notifierImpl struct{}

func (n *notifierImpl) SendShowMessage(messageType sglsp.MessageType, message string) {
	SendShowMessage(messageType, message)
}

func (n *notifierImpl) Send(msg any) {
	Send(msg)
}

func (n *notifierImpl) SendError(err error) {
	SendError(err)
}

func (n *notifierImpl) SendErrorDiagnostic(path string, err error) {
	SendErrorDiagnostic(path, err)
}

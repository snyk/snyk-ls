package notification

import (
	"github.com/sourcegraph/go-lsp"
)

// Notifier should be passed as a dependency to the types that call "notification.x" functions.
// This allows using mocks and enables us to gradually refactor out the direct calls to
// the "notification" package functions.
type Notifier interface {
	SendShowMessage(messageType lsp.MessageType, message string)
	Send(msg any)
	SendError(err error)
	SendErrorDiagnostic(path string, err error)
	Receive() (payload any, stop bool)
	CreateListener(callback func(params any))
	DisposeListener()
}

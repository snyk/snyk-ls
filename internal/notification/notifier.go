package notification

import sglsp "github.com/sourcegraph/go-lsp"

// Notifier should be passed as a dependency to the types that call "notification.x" functions.
// This allows using mocks and enables us to gradually refactor out the direct calls to
// the "notification" package functions.
type Notifier interface {
	SendShowMessage(messageType sglsp.MessageType, message string)
	Send(msg any)
	SendError(err error)
	SendErrorDiagnostic(path string, err error)
	Receive() (payload any, stop bool)
	CreateListener(callback func(params any))
	DisposeListener()
}

var _ Notifier = &notifierImpl{}

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

func (n *notifierImpl) Receive() (payload any, stop bool) {
	return Receive()
}

func (n *notifierImpl) CreateListener(callback func(params any)) {
	CreateListener(callback)
}

func (n *notifierImpl) DisposeListener() {
	DisposeListener()
}

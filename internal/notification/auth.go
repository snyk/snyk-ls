package notification

import "github.com/snyk/snyk-ls/lsp"

type Event string

var channel = make(chan lsp.AuthenticationParams, 1)

func Send(token string) {
	channel <- lsp.AuthenticationParams{Token: token}
}

func Receive() lsp.AuthenticationParams {
	return <-channel
}

func CreateListener(callback func(params lsp.AuthenticationParams)) {
	go func() {
		for {
			callback(Receive())
		}
	}()
}

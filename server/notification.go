package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog/log"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"
)

type Server interface {
	Notify(ctx context.Context, method string, params interface{}) error
	Callback(ctx context.Context, method string, params interface{}) (*jrpc2.Response, error)
}

var progressStopChan = make(chan bool, 1)

// TODO: To keep the protocol backwards compatible servers are only allowed to use window/workDoneProgress/create request if the client signals corresponding support using the client capability window.workDoneProgress which is defined as follows: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#progress
func createProgressListener(progressChannel chan lsp.ProgressParams, server Server) {
	for {
		select {
		case progress := <-progressChannel:
			if progress.Value == nil {
				_, err := server.Callback(context.Background(), "window/workDoneProgress/create", progress) // response is void, see https://microsoft.github.io/language-server-protocol/specification#window_workDoneProgress_create

				if err != nil {
					log.Error().Err(err).Str("method", "window/workDoneProgress/create").Msg("error while sending workDoneProgress request")
					// todo: In case an error occurs a server must not send any progress notification using the token provided in the request.
				}
			} else {
				_ = server.Notify(context.Background(), "$/progress", progress)
			}
		case <-progressStopChan:
			return
		}
	}
}

func disposeProgressListener() { // todo: verify if still needed
	progressStopChan <- true
}

func CancelProgress(token lsp.ProgressToken) {
	progress.CancelProgressChannel <- token
}

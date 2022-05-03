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

func createProgressListener(progressChannel chan lsp.ProgressParams, server Server) {
	for {
		select {
		case progress := <-progressChannel:
			if progress.Value == nil {
				_, err := server.Callback(context.Background(), "window/workDoneProgress/create", progress) // response is void, see https://microsoft.github.io/language-server-protocol/specification#window_workDoneProgress_create

				if err != nil {
					log.Error().Err(err).Str("method", "window/workDoneProgress/create").Msg("error while sending workDoneProgress request")

					// In case an error occurs a server must not send any progress notification using the token provided in the request.
					CancelProgress(progress.Token)
				}
			} else {
				_ = server.Notify(context.Background(), "$/progress", progress)
			}
		case <-progressStopChan:
			return
		}
	}
}

func disposeProgressListener() {
	progressStopChan <- true
}

func CancelProgress(token lsp.ProgressToken) {
	progress.CancelProgressChannel <- token
}

func authenticationNotification(srv **jrpc2.Server, params lsp.AuthenticationParams) {
	log.Debug().Str("method", "authenticationNotification").Msgf("Notifying server with token")
	err := (*srv).Notify(context.Background(), "$/hasAuthenticated", params)
	logError(err, "authenticationNotification")
}

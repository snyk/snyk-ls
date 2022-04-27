package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/lsp"
)

func authenticationNotification(srv **jrpc2.Server, params lsp.AuthenticationParams) {
	log.Debug().Str("method", "authenticationNotification").Msgf("Notifying server with token")
	err := (*srv).Notify(context.Background(), "$/hasAuthenticated", params)
	logError(err, "authenticationNotification")
}

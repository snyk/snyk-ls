package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"
	"golang.design/x/clipboard"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/notification"
)

func ExecuteCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (interface{}, error) {
		// The context provided by the JSON-RPC server is cancelled once a new message is being processed,
		// so we don't want to propagate it to functions that start background operations
		bgCtx := context.Background()

		method := "ExecuteCommandHandler"
		log.Info().Str("method", method).Interface("command", params).Msg("RECEIVING")
		defer log.Info().Str("method", method).Interface("command", params).Msg("SENDING")
		args := params.Arguments
		switch params.Command {
		case snyk.NavigateToRangeCommand:
			if len(args) < 2 {
				log.Warn().Str("method", method).Msg("received NavigateToRangeCommand without range")
			}
			navigateToLocation(srv, args)
		case snyk.WorkspaceScanCommand:
			workspace.Get().ClearCache(bgCtx)
			workspace.Get().ScanWorkspace(bgCtx)
		case snyk.OpenBrowserCommand:
			command.OpenBrowser(params.Arguments[0].(string))
		case snyk.LoginCommand:
			_, err := di.Authenticator().Provider().Authenticate(context.Background())
			if err != nil {
				log.Err(err).Msg("Error on snyk.login command")
				notification.SendError(err)
			}
		case snyk.CopyAuthLinkCommand:
			url := di.Authenticator().Provider().AuthURL(bgCtx)

			err := clipboard.Init()
			if err != nil {
				log.Err(err).Msg("Error on snyk.copyAuthLink command")
				notification.SendError(err)
				break
			}

			clipboard.Write(clipboard.FmtText, []byte(url))
		}
		return nil, nil
	})
}

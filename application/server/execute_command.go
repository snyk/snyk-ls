package server

import (
	"context"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
)

func ExecuteCommandHandler(srv *jrpc2.Server) jrpc2.Handler {
	return handler.New(func(ctx context.Context, params sglsp.ExecuteCommandParams) (interface{}, error) {
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
			workspace.Get().ClearCache(ctx)
			workspace.Get().ScanWorkspace(ctx)
		case snyk.OpenBrowserCommand:
			command.OpenBrowser(params.Arguments[0].(string))
		case snyk.CopyAuthLinkCommand:
			err := di.Authenticator().Provider().AuthURL(ctx)
			if err != nil {
				log.Err(err).Msg("Error on snyk.copyAuthLink command")
			}
		}
		return nil, nil
	})
}

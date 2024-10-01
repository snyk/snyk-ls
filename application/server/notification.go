/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"context"
	"reflect"

	"github.com/rs/zerolog"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/types"
)

func notifier(c *config.Config, srv types.Server, method string, params any) {
	c.Logger().Debug().Str("method", "notifier").Str("type", reflect.TypeOf(params).String()).Msgf("Notifying")
	err := srv.Notify(context.Background(), method, params)
	logError(c.Logger(), err, "notifier")
}

var progressStopChan = make(chan bool, 1000)

func createProgressListener(progressChannel chan types.ProgressParams, server types.Server, logger *zerolog.Logger) {
	// cleanup stopchannel before starting
	for {
		select {
		case <-progressStopChan:
			continue
		default:
			break
		}
		break
	}
	logger.Debug().Msg("started progress listener")
	defer logger.Debug().Msg("stopped progress listener")
	for {
		select {
		case p := <-progressChannel:
			// on beginning a progress, we need to create it with a callback
			if _, ok := p.Value.(types.WorkDoneProgressBegin); ok {
				logger.Debug().Msg("sending create progress msg")
				_, err := server.Callback(context.Background(), "window/workDoneProgress/create", p) // response is void, see https://microsoft.github.io/language-server-protocol/specification#window_workDoneProgress_create
				if err != nil {
					logger.Error().
						Err(err).
						Str("method", "window/workDoneProgress/create").
						Msg("error while sending workDoneProgress request")
				}
			}
			notifyProgress(server, p)
		case <-progressStopChan:
			logger.Debug().Msg("received stop message for progress listener")
			return
		}
	}
}

func notifyProgress(server types.Server, p types.ProgressParams) {
	_ = server.Notify(context.Background(), "$/progress", p)
}

func disposeProgressListener() {
	progressStopChan <- true
}

func registerNotifier(c *config.Config, srv types.Server) {
	logger := c.Logger().With().Str("method", "registerNotifier").Logger()
	callbackFunction := func(params any) {
		switch params := params.(type) {
		case types.FolderConfigsParam:
			notifier(c, srv, "$/snyk.folderConfigs", params)
			logger.Debug().Any("folderConfig", params).Msg("sending folderConfig to client")
		case types.AuthenticationParams:
			notifier(c, srv, "$/snyk.hasAuthenticated", params)
			logger.Debug().Msg("sending token")
		case types.SnykIsAvailableCli:
			notifier(c, srv, "$/snyk.isAvailableCli", params)
			logger.Debug().Msg("sending cli path")
		case sglsp.ShowMessageParams:
			notifier(c, srv, "window/showMessage", params)
			logger.Debug().Interface("message", params).Msg("showing message")
		case types.DiagnosticsOverviewParams:
			logger.Debug().
				Msgf("received diagnostics overview for %s, discarding", params.Product)
		case types.PublishDiagnosticsParams:
			notifier(c, srv, "textDocument/publishDiagnostics", params)
			notifier(c, srv, "$/snyk.publishDiagnostics316", params)
			source := "LSP"
			if len(params.Diagnostics) > 0 {
				source = params.Diagnostics[0].Source
			}
			logger.Debug().
				Interface("documentURI", params.URI).
				Interface("source", source).
				Interface("diagnosticCount", len(params.Diagnostics)).
				Msg("publishing diagnostics")
		case types.SnykTrustedFoldersParams:
			notifier(c, srv, "$/snyk.addTrustedFolders", params)
			logger.Info().
				Interface("trustedPaths", params.TrustedFolders).
				Msg("sending trusted Folders to client")
		case types.SnykScanParams:
			notifier(c, srv, "$/snyk.scan", params)
			logger.Info().
				Interface("product", params.Product).
				Interface("status", params.Status).
				Msg("sending scan data to client")
		case types.ShowMessageRequest:
			// Function blocks on callback, so we need to run it in a separate goroutine
			go handleShowMessageRequest(srv, params, &logger)
			logger.Debug().Msg("sending show message request to client")
		case types.ApplyWorkspaceEditParams:
			handleApplyWorkspaceEdit(srv, params, &logger)
			logger.Debug().
				Msg("sending apply workspace edit request to client")
		case types.CodeLensRefresh:
			handleCodelensRefresh(srv, &logger)
			logger.Debug().
				Msg("sending codelens refresh request to client")
		case types.InlineValueRefresh:
			handleInlineValueRefresh(srv, &logger)
			logger.Debug().
				Msg("sending inline value refresh request to client")
		default:
			logger.Warn().
				Interface("params", params).
				Msg("received unconfigured notification object")
		}
	}
	di.Notifier().CreateListener(callbackFunction)
	logger.Debug().Str("method", "registerNotifier").Msg("registered notifier")
}

func handleInlineValueRefresh(srv types.Server, logger *zerolog.Logger) {
	method := "handleInlineValueRefresh"
	if !config.CurrentConfig().ClientCapabilities().Workspace.InlineValue.RefreshSupport {
		logger.Debug().Str("method", method).Msg("inlineValue/refresh not supported by client, not sending request")
		return
	}
	logger.Debug().Str("method", method).Msg("sending inline value refresh request to client")

	_, err := srv.Callback(context.Background(), "workspace/inlineValue/refresh", nil)
	if err != nil {
		logger.Err(err).Str("method", method).
			Msg("error while sending workspace/inlineValue/refresh request")
		return
	}
}

func handleCodelensRefresh(srv types.Server, logger *zerolog.Logger) {
	method := "handleCodeLensRefresh"
	if !config.CurrentConfig().ClientCapabilities().Workspace.CodeLens.RefreshSupport {
		logger.Debug().Str("method", method).Msg("codelens/refresh not supported by client, not sending request")
		return
	}
	logger.Debug().Str("method", method).Msg("sending codelens refresh request to client")

	_, err := srv.Callback(context.Background(), "workspace/codeLens/refresh", nil)
	if err != nil {
		logger.Err(err).Str("method", method).
			Msg("error while sending workspace/codeLens/refresh request")
		return
	}
}

func handleApplyWorkspaceEdit(srv types.Server, params types.ApplyWorkspaceEditParams, logger *zerolog.Logger) {
	method := "handleApplyWorkspaceEdit"
	if !config.CurrentConfig().ClientCapabilities().Workspace.ApplyEdit {
		logger.Debug().Str("method", method).Msg("workspace/applyEdit not supported by client, not sending request")
		return
	}
	callback, err := srv.Callback(context.Background(), "workspace/applyEdit", params)
	if err != nil {
		logger.Err(err).Str("method", method).Msg("error while sending workspace/applyEdit request")
		return
	}
	if callback == nil {
		return
	}

	var editResult types.ApplyWorkspaceEditResult
	err = callback.UnmarshalResult(&editResult)
	if err != nil {
		logger.Err(err).Str("method", method).Msg("error while unmarshalling workspace/applyEdit result response")
		return
	}

	logger.Debug().Str("method", method).
		Msgf("Workspace edit applied %t. %s", editResult.Applied, editResult.FailureReason)
}

func handleShowMessageRequest(srv types.Server, params types.ShowMessageRequest, logger *zerolog.Logger) {
	// convert our internal message request to LSP message request
	requestParams := types.ShowMessageRequestParams{
		Type:    params.Type,
		Message: params.Message,
	}
	for _, action := range params.Actions.Keys() {
		requestParams.Actions = append(requestParams.Actions, types.MessageActionItem{
			Title: string(action),
		})
	}
	logger.Debug().
		Str("method", "registerNotifier").
		Interface("message", requestParams).
		Msg("showing message request")

	callback, err := srv.Callback(context.Background(), "window/showMessageRequest", requestParams)
	if err != nil {
		logger.Error().
			Err(err).
			Str("method", "registerNotifier").
			Msg("error while sending message request")
		return
	}
	if callback != nil {
		var actionItem types.MessageActionItem
		err = callback.UnmarshalResult(&actionItem)
		if err != nil {
			logger.Error().
				Err(err).
				Str("method", "registerNotifier").
				Msg("error while unmarshalling message request response")
			return
		}

		selectedCommand, ok := params.Actions.Get(types.MessageAction(actionItem.Title))
		if !ok {
			logger.Warn().Str("method", "registerNotifier").Msg("Action map key not found")
			return
		}
		if selectedCommand.CommandId == "" {
			logger.Info().Str("method", "registerNotifier").Msg("No command provided")
			return
		}

		_, err := command.Service().ExecuteCommandData(context.Background(), selectedCommand, srv)
		if err != nil {
			logger.Error().
				Err(err).
				Str("method", "registerNotifier").
				Msg("failed to execute command")
			return
		}
	}
}

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

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/server"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/progress"
)

func notifier(srv server.Server, method string, params any) {
	log.Debug().Str("method", "notifier").Msgf("Notifying")
	err := srv.Notify(context.Background(), method, params)
	logError(err, "notifier")
}

var progressStopChan = make(chan bool, 1000)

func createProgressListener(progressChannel chan lsp.ProgressParams, server server.Server) {
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
	log.Debug().Str("method", "createProgressListener").Msg("started listener")
	defer log.Debug().Str("method", "createProgressListener").Msg("stopped listener")
	for {
		select {
		case p := <-progressChannel:
			if p.Value == nil {
				log.Debug().Str("method", "createProgressListener").Msg("sending create progress msg ")
				_, err := server.Callback(context.Background(), "window/workDoneProgress/create", p) // response is void, see https://microsoft.github.io/language-server-protocol/specification#window_workDoneProgress_create

				if err != nil {
					log.Error().
						Err(err).
						Str("method", "window/workDoneProgress/create").
						Msg("error while sending workDoneProgress request")

					// In case an error occurs a server must not send any progress notification using the token provided in the request.
					CancelProgress(p.Token)
				}
			} else {
				log.Debug().Str("method", "createProgressListener").Interface("progress", p).Msg("sending create progress report")
				_ = server.Notify(context.Background(), "$/progress", p)
			}
		case <-progressStopChan:
			log.Debug().Str("method", "createProgressListener").Msg("received stop message")
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

func registerNotifier(srv server.Server) {
	callbackFunction := func(params any) {
		switch params := params.(type) {
		case lsp.AuthenticationParams:
			notifier(srv, "$/snyk.hasAuthenticated", params)
			log.Info().Str("method", "registerNotifier").
				Msg("sending token")
		case lsp.SnykIsAvailableCli:
			notifier(srv, "$/snyk.isAvailableCli", params)
			log.Info().Str("method", "registerNotifier").
				Msg("sending cli path")
		case sglsp.ShowMessageParams:
			notifier(srv, "window/showMessage", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("message", params).
				Msg("showing message")
		case lsp.PublishDiagnosticsParams:
			notifier(srv, "textDocument/publishDiagnostics", params)
			source := "LSP"
			if len(params.Diagnostics) > 0 {
				source = params.Diagnostics[0].Source
			}
			log.Info().
				Str("method", "registerNotifier").
				Interface("documentURI", params.URI).
				Interface("source", source).
				Interface("diagnosticCount", len(params.Diagnostics)).
				Msg("publishing diagnostics")
		case lsp.SnykTrustedFoldersParams:
			notifier(srv, "$/snyk.addTrustedFolders", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("trustedPaths", params.TrustedFolders).
				Msg("sending trusted Folders to client")
		case lsp.SnykScanParams:
			notifier(srv, "$/snyk.scan", params)
			log.Info().
				Str("method", "registerNotifier").
				Interface("product", params.Product).
				Interface("status", params.Status).
				Msg("sending scan data to client")
		case snyk.ShowMessageRequest:
			// Function blocks on callback, so we need to run it in a separate goroutine
			go handleShowMessageRequest(srv, params)
			log.Info().
				Str("method", "registerNotifier").
				Msg("sending show message request to client")

		default:
			log.Warn().
				Str("method", "registerNotifier").
				Interface("params", params).
				Msg("received unconfigured notification object")
		}
	}
	notification.CreateListener(callbackFunction)
	log.Info().Str("method", "registerNotifier").Msg("registered notifier")
}

func handleShowMessageRequest(srv server.Server, params snyk.ShowMessageRequest) {
	// convert our internal message request to LSP message request
	requestParams := lsp.ShowMessageRequestParams{
		Type:    lsp.MessageType(params.Type),
		Message: params.Message,
	}
	for _, action := range params.Actions.Keys() {
		requestParams.Actions = append(requestParams.Actions, lsp.MessageActionItem{
			Title: string(action),
		})
	}
	log.Info().
		Str("method", "registerNotifier").
		Interface("message", requestParams).
		Msg("showing message request")

	callback, err := srv.Callback(context.Background(), "window/showMessageRequest", requestParams)
	if err != nil {
		log.Error().
			Err(err).
			Str("method", "registerNotifier").
			Msg("error while sending message request")
		return
	}
	if callback != nil {
		var actionItem lsp.MessageActionItem
		err = callback.UnmarshalResult(&actionItem)
		if err != nil {
			log.Error().
				Err(err).
				Str("method", "registerNotifier").
				Msg("error while unmarshalling message request response")
			return
		}

		selectedCommand, ok := params.Actions.Get(snyk.MessageAction(actionItem.Title))
		if !ok {
			log.Info().Str("method", "registerNotifier").Msg("Action map key not found")
			return
		}
		if selectedCommand == nil {
			log.Info().Str("method", "registerNotifier").Msg("Void command selected")
			return
		}

		_, err := command.Service().ExecuteCommand(context.Background(), selectedCommand)
		if err != nil {
			log.Error().
				Err(err).
				Str("method", "registerNotifier").
				Msg("failed to execute command")
			return
		}
	}
}

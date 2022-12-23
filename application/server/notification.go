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

	"github.com/creachadair/jrpc2"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
)

func notifier(srv *jrpc2.Server, method string, params any) {
	log.Debug().Str("method", "notifier").Msgf("Notifying")
	err := srv.Notify(context.Background(), method, params)
	logError(err, "notifier")
}

type Server interface {
	Notify(ctx context.Context, method string, params any) error
	Callback(ctx context.Context, method string, params any) (*jrpc2.Response, error)
}

var progressStopChan = make(chan bool, 1000)

func createProgressListener(progressChannel chan lsp.ProgressParams, server Server) {
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

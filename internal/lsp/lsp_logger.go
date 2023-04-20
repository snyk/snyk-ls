/*
 * © 2023 Snyk Limited
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

package lsp

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type lspWriter struct {
	writeChan chan string
	readyChan chan bool
	server    Server
}

func New(server Server) io.Writer {
	log.Info().Msg("Starting LSP logger")
	readyChan := make(chan bool)
	writeChan := make(chan string, 1000000)
	w := &lspWriter{
		writeChan: writeChan,
		readyChan: readyChan,
		server:    server,
	}
	w.startServerSenderRoutine()
	// let the routine startup first
	<-w.readyChan
	log.Info().Msg("LSP logger started")
	return w
}

func (w *lspWriter) Write(p []byte) (n int, err error) {
	if w.server != nil {
		w.writeChan <- string(p)
	} else {
		_, _ = os.Stderr.Write(p)
	}
	return len(p), nil
}

func (w *lspWriter) startServerSenderRoutine() {
	go func() {
		w.readyChan <- true
		message := LogMessageParams{}
		var err error
		for s := range w.writeChan {
			// only send up to debug to the server, trace only to the console
			mt, enabled := mapLogLevel(zerolog.GlobalLevel())
			message.Message = s
			message.Type = mt
			if w.server != nil && enabled {
				err = w.server.Notify(context.Background(), "window/logMessage", message)
				if err != nil {
					_, _ = os.Stderr.Write([]byte(s))
				}
			}
		}
		fmt.Println("LSP logger stopped")
	}()
}

func mapLogLevel(level zerolog.Level) (mt MessageType, enabled bool) {
	enabled = true
	switch level {
	case zerolog.PanicLevel:
		fallthrough
	case zerolog.FatalLevel:
		fallthrough
	case zerolog.ErrorLevel:
		mt = Error
	case zerolog.WarnLevel:
		mt = Warning
	case zerolog.InfoLevel:
		mt = Info
	case zerolog.DebugLevel:
		mt = Log
	case zerolog.NoLevel:
		fallthrough
	case zerolog.TraceLevel:
		fallthrough
	case zerolog.Disabled:
		enabled = false
	}

	return mt, enabled
}

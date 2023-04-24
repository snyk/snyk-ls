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
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type lspWriter struct {
	writeChan chan LogMessageParams
	readyChan chan bool
	server    Server
}

func New(server Server) zerolog.LevelWriter {
	log.Info().Msg("Starting LSP logger")
	readyChan := make(chan bool)
	writeChan := make(chan LogMessageParams, 1000000)
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
	return os.Stderr.Write(p)
}

func (w *lspWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	levelEnabled := level > zerolog.TraceLevel && level < zerolog.NoLevel
	if w.server != nil && levelEnabled {
		w.writeChan <- LogMessageParams{
			Type:    mapLogLevel(level),
			Message: string(p),
		}
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

func (w *lspWriter) startServerSenderRoutine() {
	go func() {
		w.readyChan <- true
		var err error
		for msg := range w.writeChan {
			err = w.server.Notify(context.Background(), "window/logMessage", msg)
			if err != nil {
				_, _ = os.Stderr.Write([]byte(msg.Message))
			}
		}
		fmt.Println("LSP logger stopped")
	}()
}

func mapLogLevel(level zerolog.Level) (mt MessageType) {
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
	default:
		mt = 0
	}
	return mt
}
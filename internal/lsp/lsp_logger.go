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
)

type lspWriter struct {
	writeChan chan LogMessageParams
	readyChan chan bool
	server    Server
}

func New(server Server) zerolog.LevelWriter {
	if server != nil {
		_, _ = os.Stderr.WriteString("LSP logger: starting with non-nil server \n")
	}
	readyChan := make(chan bool)
	writeChan := make(chan LogMessageParams, 1000000)
	w := &lspWriter{
		writeChan: writeChan,
		readyChan: readyChan,
		server:    server,
	}
	go w.startServerSenderRoutine()
	// let the routine startup first
	_, _ = os.Stderr.WriteString("LSP logger: waiting for ready signal... \n")
	<-w.readyChan
	_, _ = os.Stderr.WriteString("LSP logger: started\n")
	return w
}

func (w *lspWriter) Write(p []byte) (n int, err error) {
	return w.WriteLevel(zerolog.InfoLevel, p)
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

	if levelEnabled {
		return os.Stderr.Write(p)
	}

	return 0, nil
}

func (w *lspWriter) startServerSenderRoutine() {
	w.readyChan <- true
	var err error
	for msg := range w.writeChan {
		err = w.server.Notify(context.Background(), "window/logMessage", msg)
		if err != nil {
			_, _ = os.Stderr.Write([]byte(msg.Message))
		}
	}
	fmt.Printf("LSP logger (%p) stopped", w)
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

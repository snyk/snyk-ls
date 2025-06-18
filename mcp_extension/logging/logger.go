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

package logging

import (
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
)

type mcpWriter struct {
	writeChan chan mcp.LoggingMessageNotification
	readyChan chan bool
	server    *server.MCPServer
}

func New() zerolog.LevelWriter {
	readyChan := make(chan bool)
	writeChan := make(chan mcp.LoggingMessageNotification, 1000000)
	w := &mcpWriter{
		writeChan: writeChan,
		readyChan: readyChan,
	}
	go w.startServerSenderRoutine()
	<-w.readyChan
	return w
}

func (w *mcpWriter) Write(p []byte) (n int, err error) {
	return w.WriteLevel(zerolog.InfoLevel, p)
}

func (w *mcpWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	levelEnabled := level > zerolog.TraceLevel && level < zerolog.NoLevel
	if w.server != nil && levelEnabled {

		w.writeChan <- mcp.NewLoggingMessageNotification(
			mapLogLevel(level),
			"Snyk MCP Server",
			string(p))
		return len(p), nil
	}

	if levelEnabled {
		return os.Stderr.Write(p)
	}

	return 0, nil
}

func (w *mcpWriter) startServerSenderRoutine() {
	w.readyChan <- true
	for msg := range w.writeChan {
		// Send the notification to all clients - need to create a map to pass the params correctly
		w.server.SendNotificationToAllClients(msg.Method, map[string]any{
			"level":  string(msg.Params.Level),
			"logger": "snyk-mcp",
			"data":   msg.Params.Data,
		})
	}
}

func mapLogLevel(level zerolog.Level) (mt mcp.LoggingLevel) {
	switch level {
	case zerolog.PanicLevel:
		fallthrough
	case zerolog.FatalLevel:
		mt = mcp.LoggingLevelCritical
	case zerolog.ErrorLevel:
		mt = mcp.LoggingLevelError
	case zerolog.WarnLevel:
		mt = mcp.LoggingLevelWarning
	case zerolog.InfoLevel:
		mt = mcp.LoggingLevelInfo
	case zerolog.DebugLevel:
		mt = mcp.LoggingLevelDebug
	default:
		mt = mcp.LoggingLevelInfo
	}
	return mt
}

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
	"fmt"
	"io"
	"os"
	"time"

	"github.com/adrg/xdg"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
	frameworkLogging "github.com/snyk/go-application-framework/pkg/logging"
)

type mcpWriter struct {
	writeChan chan mcp.LoggingMessageNotification
	readyChan chan bool
	server    *server.MCPServer
}

func New(server *server.MCPServer) zerolog.LevelWriter {
	readyChan := make(chan bool)
	writeChan := make(chan mcp.LoggingMessageNotification, 1000000)
	w := &mcpWriter{
		writeChan: writeChan,
		readyChan: readyChan,
		server:    server,
	}
	go w.startServerSenderRoutine()
	<-w.readyChan
	return w
}

func (w *mcpWriter) Write(p []byte) (n int, err error) {
	return w.WriteLevel(zerolog.InfoLevel, p)
}

func (w *mcpWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	if w.server != nil {
		w.writeChan <- mcp.NewLoggingMessageNotification(
			mapLogLevel(level),
			"Snyk MCP Server",
			string(p))
		return len(p), nil
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

func getConsoleWriter(writer io.Writer) zerolog.ConsoleWriter {
	w := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.Out = writer
		w.NoColor = true
		w.TimeFormat = time.RFC3339Nano
		w.PartsOrder = []string{
			zerolog.TimestampFieldName,
			zerolog.LevelFieldName,
			"method",
			"ext",
			"separator",
			zerolog.CallerFieldName,
			zerolog.MessageFieldName,
		}
		w.FieldsExclude = []string{"method", "separator", "ext"}
	})
	return w
}

func ConfigureLogging(server *server.MCPServer) *zerolog.Logger {
	logLevel := zerolog.InfoLevel

	envLogLevel := os.Getenv("SNYK_LOG_LEVEL")
	if envLogLevel != "" {
		msg := fmt.Sprint("Setting log level from environment variable (SNYK_LOG_LEVEL) \"", envLogLevel, "\"")
		_, _ = fmt.Fprintln(os.Stderr, msg)
		if envLevel, levelErr := zerolog.ParseLevel(envLogLevel); levelErr == nil {
			logLevel = envLevel
		}
	}

	mcpLevelWriter := New(server) // implements zerolog.LevelWriter

	var writers []io.Writer
	writers = append(writers, mcpLevelWriter)

	logPath, err := xdg.ConfigFile("Snyk/snyk-mcp.log")
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "couldn't get log path")
	} else if logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); err == nil {
		writers = append(writers, logFile)
	}

	scrubbingWriter := frameworkLogging.NewScrubbingWriter(zerolog.MultiLevelWriter(writers...), make(frameworkLogging.ScrubbingDict))
	writer := getConsoleWriter(scrubbingWriter)
	logger := zerolog.New(writer).With().Timestamp().Str("separator", "-").Str("method", "").Str("ext", "snyk-mcp").Logger().Level(logLevel)

	return &logger
}

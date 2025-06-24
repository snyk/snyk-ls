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

const SNYK_MCP = "snyk-mcp"

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
			SNYK_MCP,
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
			"logger": SNYK_MCP,
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

	if envLogLevel := os.Getenv("SNYK_LOG_LEVEL"); envLogLevel != "" {
		if envLevel, err := zerolog.ParseLevel(envLogLevel); err == nil {
			logLevel = envLevel
		}
	}

	var rawWriters []io.Writer

	mcpLevelWriter := New(server)
	rawWriters = append(rawWriters, mcpLevelWriter)

	if logPath, err := xdg.ConfigFile("snyk/snyk-mcp.log"); err == nil {
		if logFile, fileOpenErr := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600); fileOpenErr == nil {
			rawWriters = append(rawWriters, logFile)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "failed to open log file %s: %s\n", logPath, fileOpenErr)
		}
	}
	rawWriters = append(rawWriters, os.Stderr) // enhanced GAF logger writes to stderr

	scrubbingWriter := frameworkLogging.NewScrubbingWriter(
		zerolog.MultiLevelWriter(rawWriters...),
		make(frameworkLogging.ScrubbingDict),
	)

	consoleWriter := getConsoleWriter(scrubbingWriter)

	logger := zerolog.New(consoleWriter).With().
		Timestamp().
		Str("separator", "-").
		Str("method", "").
		Str("ext", SNYK_MCP).
		Logger().
		Level(logLevel)

	return &logger
}

/*
 * © 2024 Snyk Limited
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

package code

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	codeClient "github.com/snyk/code-client-go/observability"
)

type CodeLogger struct{}

func (l CodeLogger) Debug(err error, fields codeClient.LoggerFields, userMessage string) {
	logEvent := log.Debug()
	if err != nil {
		logEvent = logEvent.Err(err)
	}
	attachFields(logEvent, fields)
	logEvent.Msg(userMessage)
}

func (l CodeLogger) Error(err error, fields codeClient.LoggerFields, userMessage string) {
	logEvent := log.Error().Err(err)
	attachFields(logEvent, fields)
	logEvent.Msg(userMessage)
}

func (l CodeLogger) Info(fields codeClient.LoggerFields, userMessage string) {
	logEvent := log.Info()
	attachFields(logEvent, fields)
	logEvent.Msg(userMessage)
}

func (l CodeLogger) Trace(fields codeClient.LoggerFields, userMessage string) {
	logEvent := log.Trace()
	attachFields(logEvent, fields)
	logEvent.Msg(userMessage)
}

func attachFields(logEvent *zerolog.Event, fields codeClient.LoggerFields) *zerolog.Event {
	var logEventWithFields = logEvent
	for field, fieldValue := range fields {
		switch value := fieldValue.(type) {
		case int:
			logEventWithFields = logEventWithFields.Int(field, value)
			break
		case string:
			logEventWithFields = logEventWithFields.Str(field, value)
			break
		default:
			logEventWithFields = logEventWithFields.Interface(field, value)
		}
	}
	return logEventWithFields
}

func NewLogger() *CodeLogger {
	return &CodeLogger{}
}

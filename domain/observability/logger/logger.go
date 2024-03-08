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

package logger

import (
	"github.com/rs/zerolog/log"
	codeClient "github.com/snyk/code-client-go/observability"
)

type Logger struct{}

func (l Logger) Debug(err error, fields codeClient.LoggerFields, userMessage string) {
	if err == nil {
		log.Debug().Msg(userMessage)
	} else {
		log.Debug().Err(err).Msg(userMessage)
	}
}

func (l Logger) Error(err error, fields codeClient.LoggerFields, userMessage string) {
	log.Err(err).Msg(userMessage)
}

func (l Logger) Info(fields codeClient.LoggerFields, userMessage string) {
	log.Info().Msg(userMessage)
}

func (l Logger) Trace(fields codeClient.LoggerFields, userMessage string) {
	log.Trace().Msg(userMessage)
}

func NewLogger() *Logger {
	return &Logger{}
}

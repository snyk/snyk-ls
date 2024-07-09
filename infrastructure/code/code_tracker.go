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
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	codeClientScan "github.com/snyk/code-client-go/scan"

	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
)

type trackerFactory struct {
}

func NewCodeTrackerFactory() codeClientScan.TrackerFactory {
	return &trackerFactory{}
}

func (t trackerFactory) GenerateTracker() codeClientScan.Tracker {
	return newCodeTracker(progress.Channel, progress.CancelProgressChannel)
}

type tracker struct {
	token         lsp.ProgressToken
	finished      bool
	channel       chan lsp.ProgressParams
	cancelChannel chan lsp.ProgressToken
}

func newCodeTracker(channel chan lsp.ProgressParams, cancelChannel chan lsp.ProgressToken) codeClientScan.Tracker {
	return &tracker{
		channel:       channel,
		cancelChannel: cancelChannel,
		finished:      false,
	}
}

func (t *tracker) Begin(title, message string) {
	t.token = lsp.ProgressToken(uuid.New().String())

	t.send(lsp.ProgressParams{
		Token: t.token,
		Value: nil,
	})

	t.send(lsp.ProgressParams{
		Token: t.token,
		Value: lsp.WorkDoneProgressBegin{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: lsp.WorkDoneProgressBeginKind},
			Title:                title,
			Message:              message,
			Cancellable:          false,
			Percentage:           0,
		},
	})
}

func (t *tracker) End(message string) {
	if t.finished {
		panic("Called end progress twice. This breaks LSP in Eclipse. Fix me now and avoid headaches later")
	}
	t.finished = true
	t.send(lsp.ProgressParams{
		Token: t.token,
		Value: lsp.WorkDoneProgressEnd{
			WorkDoneProgressKind: lsp.WorkDoneProgressKind{Kind: lsp.WorkDoneProgressEndKind},
			Message:              message,
		},
	})
}

func (t *tracker) send(progress lsp.ProgressParams) {
	if progress.Token == "" {
		log.Error().Str("method", "send").Msg("progress token must be set")
	}
	t.channel <- progress
}

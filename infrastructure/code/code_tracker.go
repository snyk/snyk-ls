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

	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/internal/progress"
)

type trackerFactory struct {
	progressOwner *progress.Tracker
}

func NewCodeTrackerFactory(progressOwner *progress.Tracker) codeClientScan.TrackerFactory {
	return &trackerFactory{progressOwner: progressOwner}
}

// GenerateTracker takes the owner's channel rather than a registered task: this
// tracker mints its own token and code-client-go exposes no cancel hook for the
// upload phase, so a registry entry would never be resolved nor released.
func (t trackerFactory) GenerateTracker() codeClientScan.Tracker {
	return newCodeTracker(t.progressOwner.Channel())
}

type tracker struct {
	token    types.ProgressToken
	finished bool
	channel  chan types.ProgressParams
}

func newCodeTracker(channel chan types.ProgressParams) codeClientScan.Tracker {
	return &tracker{
		channel:  channel,
		finished: false,
	}
}

func (t *tracker) Begin(title, message string) {
	t.token = types.ProgressToken(uuid.New().String())

	t.send(types.ProgressParams{
		Token: t.token,
		Value: nil,
	})

	t.send(types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressBeginKind},
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
	t.send(types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressEndKind},
			Message:              message,
		},
	})
}

func (t *tracker) send(progress types.ProgressParams) {
	if progress.Token == "" {
		log.Error().Str("method", "send").Msg("progress token must be set")
	}
	t.channel <- progress
}

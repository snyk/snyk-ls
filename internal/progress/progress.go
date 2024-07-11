/*
 * © 2022 Snyk Limited All rights reserved.
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

package progress

import (
	"time"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

var Channel = make(chan types.ProgressParams, 10000)
var CancelProgressChannel = make(chan types.ProgressToken, 10000)

type Tracker struct {
	channel              chan types.ProgressParams
	cancelChannel        chan types.ProgressToken
	token                types.ProgressToken
	cancellable          bool
	lastReport           time.Time
	lastReportPercentage int
	finished             bool
}

func NewTestTracker(channel chan types.ProgressParams, cancelChannel chan types.ProgressToken) *Tracker {
	return &Tracker{
		channel:       channel,
		cancelChannel: cancelChannel,
		// deepcode ignore HardcodedPassword: false positive
		token:                "token",
		cancellable:          true,
		lastReportPercentage: -1,
	}
}

func NewTracker(cancellable bool) *Tracker {
	return &Tracker{
		channel:       Channel,
		cancelChannel: CancelProgressChannel,
		cancellable:   cancellable,
		finished:      false,
	}
}

func (t *Tracker) BeginUnquantifiableLength(title, message string) {
	t.begin(title, message, true)
}

func (t *Tracker) begin(title string, message string, unquantifiableLength bool) {
	params := newProgressParams(title, message, t.cancellable, unquantifiableLength)
	t.token = params.Token

	t.send(types.ProgressParams{
		Token: t.token,
		Value: nil,
	})

	t.send(params)
	t.lastReport = time.Now()
}

func (t *Tracker) Begin(title string) {
	t.begin(title, "", false)
}

func (t *Tracker) BeginWithMessage(title, message string) {
	t.begin(title, message, false)
}

func (t *Tracker) ReportWithMessage(percentage int, message string) {
	if time.Now().Before(t.lastReport.Add(time.Second)) || percentage <= t.lastReportPercentage {
		return
	}
	progress := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Percentage:           percentage,
			Message:              message,
		},
	}
	t.send(progress)
	t.lastReport = time.Now()
	t.lastReportPercentage = percentage
}

func (t *Tracker) Report(percentage int) {
	t.ReportWithMessage(percentage, "")
}

func (t *Tracker) End() {
	t.EndWithMessage("")
}

func (t *Tracker) EndWithMessage(message string) {
	if t.finished {
		panic("Called end progress twice. This breaks LSP in Eclipse fix me now and avoid headaches later")
	}
	t.finished = true
	progress := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressEndKind},
			Message:              message,
		},
	}

	t.send(progress)
}
func (t *Tracker) CancelOrDone(onCancel func(), doneCh chan bool) {
	for {
		select {
		case token := <-t.cancelChannel:
			if token == t.token {
				onCancel()
			}
		case <-doneCh:
			return
		}
	}
}

func (t *Tracker) GetToken() types.ProgressToken {
	return t.token
}

func newProgressParams(title, message string, cancellable, unquantifiableLength bool) types.ProgressParams {
	id := uuid.New().String()
	percentage := 1
	if unquantifiableLength {
		percentage = 0
	}
	return types.ProgressParams{
		Token: types.ProgressToken(id),
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressBeginKind},
			Title:                title,
			Message:              message,
			Cancellable:          cancellable,
			Percentage:           percentage,
		},
	}
}

func (t *Tracker) send(progress types.ProgressParams) {
	if progress.Token == "" {
		config.CurrentConfig().Logger().Error().Str("method", "send").Msg("progress has no token")
	}
	t.channel <- progress
}

func CleanupChannels() {
	for len(Channel) > 0 {
		<-Channel
	}
	for len(CancelProgressChannel) > 0 {
		<-CancelProgressChannel
	}
}

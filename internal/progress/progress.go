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
	"maps"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

var trackersMutex sync.RWMutex
var trackers = make(map[types.ProgressToken]*Tracker)
var ToServerProgressChannel = make(chan types.ProgressParams, 100000)

type Tracker struct {
	channel              chan types.ProgressParams
	cancelChannel        chan bool
	token                types.ProgressToken
	cancellable          bool
	lastReport           time.Time
	lastReportPercentage int
	finished             bool
	lastMessage          string
	m                    sync.Mutex
}

func NewTestTracker(channel chan types.ProgressParams, cancelChannel chan bool) *Tracker {
	t := &Tracker{
		channel:       channel,
		cancelChannel: cancelChannel,
		// deepcode ignore HardcodedPassword: false positive
		token:                "token",
		cancellable:          true,
		lastReportPercentage: -1,
	}
	trackersMutex.Lock()
	trackers[t.token] = t
	trackersMutex.Unlock()
	return t
}

func NewTracker(cancellable bool) *Tracker {
	t := &Tracker{
		channel:       ToServerProgressChannel,
		cancelChannel: make(chan bool, 1),
		cancellable:   cancellable,
		finished:      false,
		token:         types.ProgressToken(uuid.NewString()),
	}
	trackersMutex.Lock()
	trackers[t.token] = t
	trackersMutex.Unlock()
	return t
}

func (t *Tracker) GetChannel() chan types.ProgressParams {
	return t.channel
}

func (t *Tracker) GetCancelChannel() chan bool {
	return t.cancelChannel
}

func (t *Tracker) BeginUnquantifiableLength(title, message string) {
	t.begin(title, message, true)
}

func (t *Tracker) begin(title string, message string, unquantifiableLength bool) {
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.begin").Logger()
	params := newProgressParams(title, message, t.cancellable, unquantifiableLength)
	params.Token = t.token
	t.send(params, logger)
	t.lastReport = time.Now()
	t.setLastMessage(message)
}

func (t *Tracker) Begin(title string) {
	t.begin(title, "", false)
}

func (t *Tracker) BeginWithMessage(title, message string) {
	t.begin(title, message, false)
}

func (t *Tracker) ReportWithMessage(percentage int, message string) {
	t.m.Lock()
	defer t.m.Unlock()
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.ReportWithMessage").Logger()
	if time.Now().Before(t.lastReport.Add(200 * time.Millisecond)) {
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
	t.send(progress, logger)
	t.lastReport = time.Now()
	t.lastReportPercentage = percentage
	t.setLastMessage(message)
}

func (t *Tracker) Report(percentage int) {
	t.ReportWithMessage(percentage, "")
}

func (t *Tracker) End() {
	t.EndWithMessage("")
}

func (t *Tracker) EndWithMessage(message string) {
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.EndWithMessage").Logger()
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

	t.send(progress, logger)
}

func (t *Tracker) CancelOrDone(onCancel func(), doneCh <-chan struct{}) {
	logger := config.CurrentConfig().Logger()
	defer t.deleteTracker()
	defer onCancel()
	for {
		select {
		case <-t.cancelChannel:
			logger.Info().Msgf("Canceling Progress %s. Last message: %s", t.token, t.lastMessage)
			return
		case <-doneCh:
			logger.Info().Msgf("Received done from channel for progress %s", t.token)
			return
		}
	}
}

func (t *Tracker) deleteTracker() {
	trackersMutex.Lock()
	delete(trackers, t.token)
	trackersMutex.Unlock()
}

func (t *Tracker) GetToken() types.ProgressToken {
	return t.token
}

func newProgressParams(title, message string, cancellable, unquantifiableLength bool) types.ProgressParams {
	percentage := 1
	if unquantifiableLength {
		percentage = 0
	}
	return types.ProgressParams{
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressBeginKind},
			Title:                title,
			Message:              message,
			Cancellable:          cancellable,
			Percentage:           percentage,
		},
	}
}

func (t *Tracker) send(progress types.ProgressParams, logger zerolog.Logger) {
	if progress.Token == "" {
		logger.Warn().Msg("progress has no token")
	}
	t.channel <- progress
}

func (t *Tracker) setLastMessage(message string) {
	if message == "" {
		return
	}
	t.lastMessage = message
}

// CleanupChannels is Test-Only. Don't use for non-test code
func CleanupChannels() {
	for len(ToServerProgressChannel) > 0 {
		<-ToServerProgressChannel
	}

	trackersMutex.Lock()
	tempTrackers := make(map[types.ProgressToken]*Tracker)
	maps.Copy(tempTrackers, trackers)
	trackersMutex.Unlock()

	for token := range tempTrackers {
		Cancel(token)
	}
}

func (t *Tracker) IsCanceled() bool {
	return IsCanceled(t.token)
}

func Cancel(token types.ProgressToken) {
	trackersMutex.Lock()
	defer trackersMutex.Unlock()
	t, ok := trackers[token]
	if ok {
		t.cancelChannel <- true
		delete(trackers, token)
		close(t.cancelChannel)
	}
}

func IsCanceled(token types.ProgressToken) bool {
	trackersMutex.RLock()
	defer trackersMutex.RUnlock()
	_, ok := trackers[token]
	return !ok
}

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
	"github.com/snyk/snyk-ls/internal/util"
)

var trackersMutex sync.RWMutex
var trackers = make(map[types.ProgressToken]*Tracker)
var ToServerProgressChannel = make(chan types.ProgressParams, 100000)

type Tracker struct {
	channel              chan types.ProgressParams
	cancelChannel        chan bool
	token                types.ProgressToken
	cancellable          bool
	unquantifiableLength bool
	lastReport           time.Time
	begun                bool
	finished             bool
	lastPercentage       int
	lastMessage          string
	m                    sync.RWMutex
}

func NewTestTracker(channel chan types.ProgressParams, cancelChannel chan bool) *Tracker {
	t := &Tracker{
		channel:       channel,
		cancelChannel: cancelChannel,
		// deepcode ignore HardcodedPassword: false positive
		token:       "token",
		cancellable: true,
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
	t.m.RLock()
	defer t.m.RUnlock()
	return t.channel
}

func (t *Tracker) GetCancelChannel() chan bool {
	t.m.RLock()
	defer t.m.RUnlock()
	return t.cancelChannel
}

func (t *Tracker) BeginUnquantifiableLength(title, message string) {
	t.m.Lock()
	defer t.m.Unlock()
	t.begin(title, message, true)
}

func (t *Tracker) begin(title string, message string, unquantifiableLength bool) {
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.begin").Logger()
	if t.begun {
		logger.Error().Msg("tracker tried to begin when already previously begun")
		return
	}
	if t.finished {
		logger.Error().Msg("tracker tried to begin when finished but not begun (race condition?)")
		return
	}
	t.begun = true
	t.unquantifiableLength = unquantifiableLength
	params := newProgressParams(title, message, t.cancellable, unquantifiableLength)
	params.Token = t.token
	t.send(params, logger)
	t.setLastMessage(message)
}

func (t *Tracker) Begin(title string) {
	t.m.Lock()
	defer t.m.Unlock()
	t.begin(title, "", false)
}

func (t *Tracker) BeginWithMessage(title, message string) {
	t.m.Lock()
	defer t.m.Unlock()
	t.begin(title, message, false)
}

func (t *Tracker) reportWithMessage(percentage int, message string) {
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.ReportWithMessage").Logger()
	if !t.begun {
		logger.Error().Msg("tried to report tracker progress when never begun")
		return
	}
	if t.finished {
		logger.Error().Msg("tried to report tracker progress when already finished")
		return
	}
	if percentage != 100 && message == t.lastMessage && (t.unquantifiableLength || percentage-10 <= t.lastPercentage) && time.Now().Before(t.lastReport.Add(200*time.Millisecond)) {
		return
	}
	progress := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Percentage:           util.Ternary(t.unquantifiableLength, nil, &percentage),
			Message:              message,
		},
	}
	t.send(progress, logger)
	t.lastReport = time.Now()
	t.lastPercentage = percentage
	t.setLastMessage(message)
}

func (t *Tracker) ReportWithMessage(percentage int, message string) {
	t.m.Lock()
	defer t.m.Unlock()
	t.reportWithMessage(percentage, message)
}

func (t *Tracker) Report(percentage int) {
	t.m.Lock()
	defer t.m.Unlock()
	t.reportWithMessage(percentage, "")
}

func (t *Tracker) End() {
	t.m.Lock()
	defer t.m.Unlock()
	t.endWithMessage("")
}

func (t *Tracker) EndWithMessage(message string) {
	t.m.Lock()
	defer t.m.Unlock()
	t.endWithMessage(message)
}

func (t *Tracker) endWithMessage(message string) {
	logger := config.CurrentConfig().Logger().With().Str("token", string(t.token)).Str("method", "progress.EndWithMessage").Logger()
	if t.finished {
		panic("Called end progress twice. This breaks LSP in Eclipse fix me now and avoid headaches later")
	}
	t.finished = true
	if !t.begun {
		// Not an error, but could be a sign of something wrong, so just log and we'll error on re-use
		logger.Debug().Msg("tracker ended when never begun")
		return
	}
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
			t.m.Lock()
			logger.Debug().Msgf("Canceling Progress %s. Last message: %s", t.token, t.lastMessage)
			t.m.Unlock()
			return
		case <-doneCh:
			t.m.Lock()
			logger.Debug().Msgf("Received done from channel for progress %s", t.token)
			t.m.Unlock()
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
	t.m.RLock()
	defer t.m.RUnlock()
	return t.token
}

func newProgressParams(title, message string, cancellable, unquantifiableLength bool) types.ProgressParams {
	return types.ProgressParams{
		Value: types.WorkDoneProgressBegin{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressBeginKind},
			Title:                title,
			Message:              message,
			Cancellable:          cancellable,
			// We must decide now if the tracker will report percentages or not, and omit the field now if not,
			// otherwise VS Code won't allow changing the message.
			// In some IDEs 0% looks like an unquantifiable progress bar, whereas in others it does not.
			Percentage: util.Ternary(unquantifiableLength, nil, util.Ptr(0)),
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
	t.m.RLock()
	defer t.m.RUnlock()
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

/*
 * © 2026 Snyk Limited All rights reserved.
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

// Task is the per-operation progress handle. One Task represents a single
// in-flight progress operation. Obtain a Task from Tracker.New(cancellable)
// when you need owner-managed cancellation, or from NewTaskWithChannel when
// you hold a channel reference directly.
//
// All ui.ProgressBar methods (Begin/Report/End/Clear/CancelOrDone/…) are
// implemented here.

import (
	"math"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/internal/types"
)

// Task is a single in-flight progress operation owned by a *Tracker.
// It implements ui.ProgressBar (verified by the compile-time assertion in
// tracker.go).
type Task struct {
	owner                *Tracker
	channel              chan types.ProgressParams
	cancelChannel        chan bool
	token                types.ProgressToken
	cancellable          bool
	lastReport           time.Time
	lastReportPercentage int
	finished             bool
	lastMessage          string
	m                    sync.Mutex
	logger               *zerolog.Logger
}

// GetToken returns the unique token for this task.
func (t *Task) GetToken() types.ProgressToken {
	return t.token
}

// GetChannel returns the progress event channel this task writes to.
func (t *Task) GetChannel() chan types.ProgressParams {
	return t.channel
}

// GetCancelChannel returns the channel on which a cancel signal is delivered.
func (t *Task) GetCancelChannel() chan bool {
	return t.cancelChannel
}

// IsCanceled delegates to the owner registry: the task is canceled when it has
// been removed from the registry. For ownerless tasks (created by
// NewTaskWithChannel), always returns false.
func (t *Task) IsCanceled() bool {
	if t.owner == nil {
		return false
	}
	return t.owner.IsCanceled(t.token)
}

// Begin starts an unquantifiable-length progress operation.
func (t *Task) BeginUnquantifiableLength(title, message string) {
	t.begin(title, message, true)
}

func (t *Task) begin(title, message string, unquantifiableLength bool) {
	logger := t.logger.With().Str("token", string(t.token)).Str("method", "Task.begin").Logger()
	params := newTaskProgressParams(title, message, t.cancellable, unquantifiableLength)
	params.Token = t.token
	t.send(params, logger)
	t.lastReport = time.Now()
	t.setLastMessage(message)
}

// Begin starts a quantifiable progress operation.
func (t *Task) Begin(title string) {
	t.begin(title, "", false)
}

// BeginWithMessage starts a quantifiable progress operation with an initial message.
func (t *Task) BeginWithMessage(title, message string) {
	t.begin(title, message, false)
}

// SetTitle updates the progress title. If the task has not begun yet, it calls
// Begin; otherwise it issues a report at the last-known percentage.
func (t *Task) SetTitle(title string) {
	t.m.Lock()
	started := !t.lastReport.IsZero()
	percentage := t.lastReportPercentage
	t.m.Unlock()

	if !started {
		t.Begin(title)
		return
	}

	if percentage < 0 {
		percentage = 0
	}
	t.ReportWithMessage(percentage, title)
}

// UpdateProgress converts a [0,1] float to a percentage and calls Report.
func (t *Task) UpdateProgress(progress float64) error {
	if math.IsNaN(progress) || math.IsInf(progress, 0) {
		progress = 0
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	t.Report(int(math.Round(progress * 100)))
	return nil
}

// ReportWithMessage sends a progress report with a percentage and message.
// Reports are rate-limited to one per 200 ms.
func (t *Task) ReportWithMessage(percentage int, message string) {
	t.m.Lock()
	defer t.m.Unlock()
	logger := t.logger.With().Str("token", string(t.token)).Str("method", "Task.ReportWithMessage").Logger()
	if time.Now().Before(t.lastReport.Add(200 * time.Millisecond)) {
		return
	}
	params := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressReport{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressReportKind},
			Percentage:           percentage,
			Message:              message,
		},
	}
	t.send(params, logger)
	t.lastReport = time.Now()
	t.lastReportPercentage = percentage
	t.setLastMessage(message)
}

// Report sends a progress report with no message.
func (t *Task) Report(percentage int) {
	t.ReportWithMessage(percentage, "")
}

// End terminates the progress operation with no message.
func (t *Task) End() {
	t.EndWithMessage("")
}

// EndWithMessage terminates the progress operation with a final message.
// Panics if called twice (matching the existing Tracker behavior).
func (t *Task) EndWithMessage(message string) {
	logger := t.logger.With().Str("token", string(t.token)).Str("method", "Task.EndWithMessage").Logger()
	if t.finished {
		panic("Called end progress twice. This breaks LSP in Eclipse fix me now and avoid headaches later")
	}
	t.finished = true
	params := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressEndKind},
			Message:              message,
		},
	}
	t.send(params, logger)
}

// Clear terminates the progress operation (if not already finished) and
// deregisters it from the owner.
func (t *Task) Clear() error {
	logger := t.logger.With().Str("token", string(t.token)).Str("method", "Task.Clear").Logger()
	t.m.Lock()
	if t.finished {
		t.m.Unlock()
		return nil
	}
	t.finished = true
	t.m.Unlock()

	params := types.ProgressParams{
		Token: t.token,
		Value: types.WorkDoneProgressEnd{
			WorkDoneProgressKind: types.WorkDoneProgressKind{Kind: types.WorkDoneProgressEndKind},
			Message:              "",
		},
	}
	t.send(params, logger)
	if t.owner != nil {
		t.owner.delete(t.token)
	}
	return nil
}

// CancelOrDone blocks until either a cancel signal is received or doneCh is
// closed, then deregisters the task from the owner (if any) and invokes onCancel.
func (t *Task) CancelOrDone(onCancel func(), doneCh <-chan struct{}) {
	logger := t.logger
	if t.owner != nil {
		defer t.owner.delete(t.token)
	}
	defer onCancel()
	for {
		select {
		case <-t.cancelChannel:
			t.m.Lock()
			logger.Debug().Msgf("Canceling Task %s. Last message: %s", t.token, t.lastMessage)
			t.m.Unlock()
			return
		case <-doneCh:
			t.m.Lock()
			logger.Debug().Msgf("Received done from channel for Task %s", t.token)
			t.m.Unlock()
			return
		}
	}
}

// SetLastMessage sets the last message if non-empty (exported, locks).
func (t *Task) SetLastMessage(message string) {
	if message == "" {
		return
	}
	t.m.Lock()
	t.setLastMessage(message)
	t.m.Unlock()
}

// setLastMessage sets the last message if non-empty (unexported, caller holds lock).
func (t *Task) setLastMessage(message string) {
	if message == "" {
		return
	}
	t.lastMessage = message
}

func (t *Task) send(params types.ProgressParams, logger zerolog.Logger) {
	if params.Token == "" || params.Value == nil {
		logger.Warn().Any("progress", params).Msg("invalid progress param, token or value not filled")
		return
	}
	t.channel <- params
}

// newTaskProgressParams builds the initial ProgressParams for a Task.Begin call.
func newTaskProgressParams(title, message string, cancellable, unquantifiableLength bool) types.ProgressParams {
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

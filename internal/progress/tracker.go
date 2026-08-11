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

// This file defines the per-server progress owner type (Tracker) and its
// per-operation handle (Task). Together they replace the process-global
// ToServerProgressChannel, global trackers map, and package-level Cancel /
// IsCanceled functions — see the expand→contract migration plan in
// docs/requirements/architecture.md.

import (
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"

	"github.com/snyk/snyk-ls/internal/types"
)

// Compile-time assertion: *Task implements ui.ProgressBar.
var _ ui.ProgressBar = (*Task)(nil)

// -----------------------------------------------------------------------------
// Tracker — per-server progress channel + live-task registry
// -----------------------------------------------------------------------------

// Tracker is the per-server owner of the progress channel and the
// token→*Task registry. Each server instance holds exactly one Tracker;
// progress events from that server travel exclusively through its channel,
// preventing cross-server event leakage.
//
// The per-operation handle is Task (see task.go). Obtain a Task via
// Tracker.New(cancellable).
type Tracker struct {
	ch     chan types.ProgressParams
	tasks  map[types.ProgressToken]*Task
	mu     sync.RWMutex
	logger *zerolog.Logger
}

// NewTracker creates a new per-server Tracker with its own buffered
// channel (capacity 1000) and an empty task registry.
func NewTracker(logger *zerolog.Logger) *Tracker {
	return &Tracker{
		ch:     make(chan types.ProgressParams, 1000),
		tasks:  make(map[types.ProgressToken]*Task),
		logger: logger,
	}
}

// NewTrackerWithChannel creates a per-server Tracker that routes events
// to the caller-supplied channel. Intended for tests that need to inspect
// events directly.
func NewTrackerWithChannel(ch chan types.ProgressParams, logger *zerolog.Logger) *Tracker {
	return &Tracker{
		ch:     ch,
		tasks:  make(map[types.ProgressToken]*Task),
		logger: logger,
	}
}

// Channel returns the progress event channel for this Tracker. Pass this to
// createProgressListener to drain progress events to the LSP client.
func (o *Tracker) Channel() chan types.ProgressParams {
	return o.ch
}

// New creates and registers a new per-operation Task on this Tracker's channel.
// cancellable controls whether the LSP client may cancel this operation via
// window/workDoneProgress/cancel.
func (o *Tracker) New(cancellable bool) *Task {
	task := o.newTask(cancellable)
	o.register(task)
	return task
}

func (o *Tracker) newTask(cancellable bool) *Task {
	return &Task{
		owner:         o,
		channel:       o.ch,
		cancelChannel: make(chan bool, 1),
		token:         types.ProgressToken(uuid.NewString()),
		cancellable:   cancellable,
		logger:        o.logger,
	}
}

// NewScan creates and registers a Task tagged as a scan token, so IsScanToken
// returns true for it. Use this for scan operations (OSS, Code, IaC) instead of
// New. Download/install operations must continue to use New so their cancel
// events do not reset the summary panel. folderPath is the workspace folder
// this scan belongs to; FolderForScanToken hands it back so a cancel handler
// can scope a reset to this folder alone.
func (o *Tracker) NewScan(cancellable bool, folderPath types.FilePath) *Task {
	task := o.newTask(cancellable)
	// Set before the task becomes visible in the registry: a cancel arriving between
	// registration and these writes would see a task that is not flagged as a scan and
	// skip the summary-panel reset (IDE-1035).
	task.isScan = true
	task.folderPath = folderPath
	o.register(task)
	return task
}

// IsScanToken reports whether token belongs to an active scan task created via
// NewScan. Returns false once the task is removed (e.g. after Cancel or
// delete), giving the cancel handler a single source of truth without a
// parallel registry.
func (o *Tracker) IsScanToken(token types.ProgressToken) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	task, ok := o.tasks[token]
	return ok && task.isScan
}

// FolderForScanToken reports the workspace folder token belongs to, for tokens
// registered via NewScan. The second return value is false if the token is
// unknown, already consumed (e.g. by Cancel), or belongs to a non-scan task —
// callers must not fall back to resetting every folder in that case.
func (o *Tracker) FolderForScanToken(token types.ProgressToken) (types.FilePath, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	task, ok := o.tasks[token]
	if !ok || !task.isScan {
		return "", false
	}
	return task.folderPath, true
}

// Cancel signals cancellation for the task identified by token, then removes
// it from the registry. Idempotent: canceling an already-canceled token is a
// no-op.
func (o *Tracker) Cancel(token types.ProgressToken) {
	o.mu.Lock()
	defer o.mu.Unlock()
	task, ok := o.tasks[token]
	if ok {
		task.cancelChannel <- true
		delete(o.tasks, token)
		close(task.cancelChannel)
	}
}

// IsCanceled reports whether token has been canceled (i.e., removed from the
// registry). A token that was never registered also returns true (not found).
func (o *Tracker) IsCanceled(token types.ProgressToken) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.tasks[token]
	return !ok
}

// register adds task to the registry. Called by New immediately after
// construction so the task can be looked up for cancellation.
func (o *Tracker) register(task *Task) {
	o.mu.Lock()
	o.tasks[task.token] = task
	o.mu.Unlock()
}

// delete removes task from the registry. Called by every terminal path —
// Task.EndWithMessage, Task.Clear and Task.CancelOrDone.
func (o *Tracker) delete(token types.ProgressToken) {
	o.mu.Lock()
	delete(o.tasks, token)
	o.mu.Unlock()
}

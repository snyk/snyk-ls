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

// Package progress implements the progress functionality
package progress

import (
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/snyk/snyk-ls/internal/types"
)

// NewTestTask creates a standalone Task for use in tests that need to
// inject a pre-wired channel and cancel channel. The task is not
// registered with any Tracker; callers are responsible for draining
// the channels when the test ends.
func NewTestTask(channel chan types.ProgressParams, cancelChannel chan bool, logger *zerolog.Logger) *Task {
	return &Task{
		owner:         nil,
		channel:       channel,
		cancelChannel: cancelChannel,
		// deepcode ignore HardcodedPassword: false positive
		token:                "token",
		cancellable:          true,
		lastReportPercentage: -1,
		logger:               logger,
	}
}

// NewTaskWithChannel creates a standalone Task that routes progress events to
// the provided channel. This is the correct constructor for per-server
// isolation: each server passes its own channel so progress events are never
// misrouted to another server's listener.
//
// Unlike Tracker.New(), this constructor does NOT register the task with any
// Tracker. Use it when you already hold a channel reference (e.g. from
// Tracker.Channel()) and need a Task with a specific cancellable setting but
// no owner-managed registry entry.
func NewTaskWithChannel(channel chan types.ProgressParams, cancellable bool, logger *zerolog.Logger) *Task {
	return &Task{
		owner:         nil,
		channel:       channel,
		cancelChannel: make(chan bool, 1),
		cancellable:   cancellable,
		finished:      false,
		token:         types.ProgressToken(uuid.NewString()),
		logger:        logger,
	}
}

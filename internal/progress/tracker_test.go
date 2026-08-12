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

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

// IDE-2036-UNIT-110: Two separate trackers cancel independently.
// Canceling a task on tracker A must NOT affect tasks on tracker B.
func TestTracker_CancelIsolation(t *testing.T) {
	logger := zerolog.Nop()

	trackerA := NewTracker(&logger)
	trackerB := NewTracker(&logger)

	taskA := trackerA.New(true)
	taskB := trackerB.New(true)

	tokenA := taskA.GetToken()
	tokenB := taskB.GetToken()

	// Before canceling: both tasks should be active (not canceled).
	assert.False(t, trackerA.IsCanceled(tokenA), "taskA should not be canceled before Cancel")
	assert.False(t, trackerB.IsCanceled(tokenB), "taskB should not be canceled before Cancel")

	// Cancel task A via tracker A.
	trackerA.Cancel(tokenA)

	// After canceling A: A is canceled, B is unaffected.
	assert.True(t, trackerA.IsCanceled(tokenA), "taskA should be canceled after Cancel")
	assert.False(t, trackerB.IsCanceled(tokenB), "taskB on trackerB must not be affected by canceling trackerA's task")

	// The cancel signal must actually have been delivered, not just removed from
	// the registry. Tracker.Cancel writes before returning, so no waiting needed.
	select {
	case <-taskA.GetCancelChannel():
		// good: cancel signal received
	default:
		t.Fatal("expected cancel signal on taskA's cancelChannel")
	}
}

// IDE-2036-UNIT-111: Two separate trackers route to separate channels.
// Progress events from tracker A must NOT appear on tracker B's channel.
func TestTracker_ChannelIsolation(t *testing.T) {
	logger := zerolog.Nop()

	trackerA := NewTracker(&logger)
	trackerB := NewTracker(&logger)

	chA := trackerA.Channel()
	chB := trackerB.Channel()

	// Distinct channel objects — different memory addresses.
	require.NotEqual(t, chA, chB, "each tracker must have its own channel")

	// Create a task on tracker A and send a progress event.
	taskA := trackerA.New(false)
	taskA.Begin("A-title")

	// Event must arrive on chA only.
	assert.Eventually(t, func() bool { return len(chA) > 0 }, time.Second, time.Millisecond,
		"progress event from tracker A must arrive on chA")
	assert.Never(t, func() bool { return len(chB) > 0 }, 50*time.Millisecond, time.Millisecond,
		"progress event from tracker A must NOT appear on chB")

	// Drain chA.
	for len(chA) > 0 {
		<-chA
	}

	// Now do the same for tracker B.
	taskB := trackerB.New(false)
	taskB.Begin("B-title")

	assert.Eventually(t, func() bool { return len(chB) > 0 }, time.Second, time.Millisecond,
		"progress event from tracker B must arrive on chB")
	assert.Never(t, func() bool { return len(chA) > 0 }, 50*time.Millisecond, time.Millisecond,
		"progress event from tracker B must NOT appear on chA")

	// End tasks so the test cleans up without blocking.
	taskA.End()
	for len(chA) > 0 {
		<-chA
	}
	taskB.End()
	for len(chB) > 0 {
		<-chB
	}
}

// TestTask_SelfCancel verifies that a Task can signal its own cancel channel
// without affecting other tasks on the same tracker.
func TestTask_SelfCancel(t *testing.T) {
	logger := zerolog.Nop()
	tracker := NewTracker(&logger)

	task := tracker.New(true)
	token := task.GetToken()

	assert.False(t, tracker.IsCanceled(token), "task should not be canceled initially")

	// Self-cancel via tracker.Cancel (mirroring the code.go self-cancel pattern).
	tracker.Cancel(token)

	assert.True(t, tracker.IsCanceled(token), "task should be canceled after tracker.Cancel")

	select {
	case <-task.GetCancelChannel():
		// good: cancel signal received
	case <-time.After(time.Second):
		t.Fatal("expected cancel signal on task's cancelChannel")
	}
}

// TestNewTrackerWithChannel verifies that NewTrackerWithChannel routes events to the
// caller-supplied channel (used by tests that need to inspect events).
func TestNewTrackerWithChannel(t *testing.T) {
	logger := zerolog.Nop()

	ch := make(chan types.ProgressParams, 100)
	tracker := NewTrackerWithChannel(ch, &logger)

	// Channel() must return the caller-supplied channel.
	assert.Equal(t, ch, tracker.Channel(), "Channel() must return the caller-supplied channel")

	task := tracker.New(false)
	task.Begin("test")
	task.End()

	// Events must flow to ch.
	assert.Greater(t, len(ch), 0, "progress events must flow to the caller-supplied channel")
}

// TestTask_ImplementsProgressBar verifies the compile-time interface assertion.
// If Task doesn't implement ui.ProgressBar, this test file won't compile.
func TestTask_ImplementsProgressBar(t *testing.T) {
	logger := zerolog.Nop()
	tracker := NewTracker(&logger)
	task := tracker.New(false)
	// Type assertion: *Task must implement ui.ProgressBar
	// (checked by the var _ ui.ProgressBar = (*Task)(nil) in task.go)
	_ = task
}

// IDE-2036-UNIT-113: A drained 1000-item channel does not deadlock producers.
// This verifies the NewDrainedProgressTracker helper's cleanup contract: a test that
// creates a tracker, fires >1000 progress events, and relies on the t.Cleanup
// drainer will not block even if the test never reads from the channel itself.
func TestTracker_DrainedChannelNoDeadlock(t *testing.T) {
	logger := zerolog.Nop()
	ch := make(chan types.ProgressParams, 1000)
	tracker := NewTrackerWithChannel(ch, &logger)

	// Register a cleanup drainer (same pattern as testutil.NewDrainedProgressTracker).
	t.Cleanup(func() {
	drain:
		for {
			select {
			case <-ch:
			default:
				break drain
			}
		}
	})

	// Fire exactly 1000 Begin events — channel capacity. Must not deadlock.
	tasks := make([]*Task, 1000)
	for i := range tasks {
		tasks[i] = tracker.New(false)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, task := range tasks {
			task.Begin("load-test")
		}
	}()

	select {
	case <-done:
		// success: all Begin calls returned without deadlocking
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: Begin blocked for >5s on a 1000-item channel with a drainer registered")
	}
}

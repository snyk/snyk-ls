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

package scans

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanProgress_CancelScan_WithCancelFunc_ImmediateWithoutListener verifies that
// CancelScan() with a registered cancel func does NOT block waiting for Listen() to
// be scheduled. This is the regression test for IDE-2099: when many scans are queued
// concurrently the Listen goroutine may not have been scheduled before CancelScan is
// called; without SetCancelFunc the cancel signal is lost until a 5-second timeout,
// allowing the superseded scan's Execute timer to fire and increment finishedScans.
func TestScanProgress_CancelScan_WithCancelFunc_ImmediateWithoutListener(t *testing.T) {
	logger := zerolog.Nop()
	sp := NewScanProgressWithLogger(&logger)

	ctx, cancel := context.WithCancel(context.Background())
	sp.SetCancelFunc(cancel)
	// Intentionally do NOT start Listen() — CancelScan must not block.

	done := make(chan struct{})
	go func() {
		sp.CancelScan()
		close(done)
	}()

	select {
	case <-done:
		// Expected: returned immediately without waiting for a channel receiver.
	case <-time.After(time.Second):
		assert.Fail(t, "CancelScan blocked even though SetCancelFunc was called — goroutine-readiness race not fixed")
	}

	assert.True(t, sp.IsDone())
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "context must be canceled by CancelScan")
}

func TestScanProgress_SetDone_DoesNotBlockAfterContextCanceled(t *testing.T) {
	logger := zerolog.Nop()
	sp := NewScanProgressWithLogger(&logger)

	ctx, cancel := context.WithCancel(context.Background())

	listenDone := make(chan struct{})
	go func() {
		sp.Listen(ctx, cancel, 1)
		close(listenDone)
	}()

	// Cancel the context, causing Listen to exit via ctx.Done()
	cancel()

	// Wait for Listen to fully exit before calling SetDone
	select {
	case <-listenDone:
	case <-time.After(time.Second):
		require.Fail(t, "Listen goroutine did not exit within 1 second after context cancel")
	}

	// SetDone must complete quickly (well under the 5-second channel timeout).
	// Without the fix, it blocks for 5 seconds because done channel has no listener.
	done := make(chan struct{})
	go func() {
		sp.SetDone()
		close(done)
	}()

	select {
	case <-done:
		// Expected: SetDone returned quickly
	case <-time.After(time.Second):
		assert.Fail(t, "SetDone blocked after Listen exited via ctx.Done() — unbuffered done channel has no listener")
	}
}

func TestScanProgress_SetDone_MarksIsDone(t *testing.T) {
	logger := zerolog.Nop()
	sp := NewScanProgressWithLogger(&logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenDone := make(chan struct{})
	go func() {
		sp.Listen(ctx, cancel, 1)
		close(listenDone)
	}()

	sp.SetDone()

	select {
	case <-listenDone:
	case <-time.After(time.Second):
		require.Fail(t, "Listen goroutine did not exit within 1 second after SetDone")
	}

	assert.True(t, sp.IsDone())
}

func TestScanProgress_CancelScan_MarksIsDone(t *testing.T) {
	logger := zerolog.Nop()
	sp := NewScanProgressWithLogger(&logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenDone := make(chan struct{})
	go func() {
		sp.Listen(ctx, cancel, 1)
		close(listenDone)
	}()

	sp.CancelScan()

	select {
	case <-listenDone:
	case <-time.After(time.Second):
		require.Fail(t, "Listen goroutine did not exit within 1 second after CancelScan")
	}

	assert.True(t, sp.IsDone())
}

// TestScanProgress_SetCancelFunc_CancelScan_NoRace verifies that concurrent
// SetCancelFunc and CancelScan on the same *ScanProgress do not race on
// sp.cancelFunc. Without the mutex in SetCancelFunc the Go race detector
// reports a DATA RACE on that field.
//
// Design note: a cancel func is pre-registered so CancelScan never falls into
// the 5-second legacy-channel fallback. A start barrier synchronizes the two
// goroutines so they race as tightly as possible.
func TestScanProgress_SetCancelFunc_CancelScan_NoRace(t *testing.T) {
	logger := zerolog.Nop()

	for i := 0; i < 500; i++ {
		sp := NewScanProgressWithLogger(&logger)

		// Pre-register a cancel func so CancelScan never blocks in the legacy path.
		_, preCancel := context.WithCancel(context.Background())
		sp.SetCancelFunc(preCancel)

		_, newCancel := context.WithCancel(context.Background())

		barrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-barrier
			sp.SetCancelFunc(newCancel) // concurrent write — SetCancelFunc holds sp.mutex; race detector confirms no data race
		}()

		go func() {
			defer wg.Done()
			<-barrier
			sp.CancelScan() // reads sp.cancelFunc under mutex
		}()

		close(barrier) // release both goroutines simultaneously
		wg.Wait()
	}
}

func TestScanProgress_SetDone_SafeToCallMultipleTimes(t *testing.T) {
	logger := zerolog.Nop()
	sp := NewScanProgressWithLogger(&logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go sp.Listen(ctx, cancel, 1)

	sp.SetDone()

	// Second call must return immediately without blocking
	done := make(chan struct{})
	go func() {
		sp.SetDone()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		assert.Fail(t, "second SetDone() call blocked")
	}

	assert.True(t, sp.IsDone())
}

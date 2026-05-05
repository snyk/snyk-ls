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
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

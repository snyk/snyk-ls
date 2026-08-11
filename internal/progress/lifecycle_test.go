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
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/types"
)

func (o *Tracker) registrySize() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.tasks)
}

// halfRegisteredScanCount counts registered tasks that would answer a cancel the
// way a non-scan task does — evaluating the same predicate IsScanToken and
// FolderForScanToken evaluate, over every entry, under the one lock they use.
func (o *Tracker) halfRegisteredScanCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	count := 0
	for _, task := range o.tasks {
		if !task.isScan || task.folderPath == "" {
			count++
		}
	}
	return count
}

func drain(t *testing.T, ch chan types.ProgressParams) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-ch:
			case <-done:
				return
			}
		}
	}()
}

// Ending a task is a terminal path just like clearing it, so it must release the
// registry entry too. The CLI downloader and every framework progress bar end
// without clearing; leaving their entries behind grows the registry for the life
// of the server.
func TestTask_End_ReleasesRegistryEntry(t *testing.T) {
	logger := zerolog.Nop()
	ch := make(chan types.ProgressParams, 10)
	tracker := NewTrackerWithChannel(ch, &logger)

	task := tracker.New(false)
	require.Equal(t, 1, tracker.registrySize(), "precondition: New registers the task")

	task.Begin("title")
	task.EndWithMessage("done")

	assert.Zero(t, tracker.registrySize(),
		"EndWithMessage must release the registry entry — a server that ends bars without clearing them must not accumulate tasks")
}

func TestTask_EndAfterEnd_StillPanics(t *testing.T) {
	logger := zerolog.Nop()
	ch := make(chan types.ProgressParams, 10)
	tracker := NewTrackerWithChannel(ch, &logger)

	task := tracker.New(false)
	task.End()

	assert.Panics(t, func() { task.End() },
		"releasing the registry entry must not weaken the double-end guard")
}

// End and Clear both read and write the finished flag; they must do so under the
// same mutex, which is what `-race` checks here. Whichever loses is allowed to
// panic (double-end is a programming error), but exactly one must have released
// the registry entry.
func TestTask_ConcurrentEndAndClear_ReleasesRegistryEntry(t *testing.T) {
	logger := zerolog.Nop()
	ch := make(chan types.ProgressParams, 1000)
	drain(t, ch)
	tracker := NewTrackerWithChannel(ch, &logger)

	const tasks = 100
	var wg sync.WaitGroup
	for range tasks {
		task := tracker.New(false)
		wg.Go(func() {
			defer func() { _ = recover() }() // losing the double-end race is expected
			task.End()
		})
		wg.Go(func() {
			_ = task.Clear()
		})
	}
	wg.Wait()

	assert.Zero(t, tracker.registrySize(),
		"every task must be released by whichever terminal path won")
}

// A cancel arriving right after NewScan must see a scan token carrying its folder:
// both fields have to be set before the task becomes visible in the registry, or
// the cancel handler skips the summary-panel reset (IDE-1035). The window is a lock
// acquisition wide, so an observer samples the registry while scans are minted —
// with the fields set after registration this fires in the thousands.
func TestTracker_NewScan_TokenIsNeverVisibleAsNonScan(t *testing.T) {
	logger := zerolog.Nop()
	ch := make(chan types.ProgressParams, 1000)
	tracker := NewTrackerWithChannel(ch, &logger)

	const rounds = 500
	stop := make(chan struct{})
	var observerWg, creatorWg sync.WaitGroup

	var mu sync.Mutex
	var sightings int

	for range 2 {
		observerWg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if n := tracker.halfRegisteredScanCount(); n > 0 {
					mu.Lock()
					sightings += n
					mu.Unlock()
				}
			}
		})
	}

	for range 2 {
		creatorWg.Go(func() {
			for range rounds {
				task := tracker.NewScan(true, "folderA")
				tracker.delete(task.GetToken())
			}
		})
	}
	creatorWg.Wait()
	close(stop)
	observerWg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, sightings,
		"a registered scan task must always resolve as a scan token for its folder; setting the fields after registration leaves a window where a cancel is treated as a non-scan cancel")
}

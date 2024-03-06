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

package scans

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const timeout = 5 * time.Second

// ScanProgress is a type that's used for tracking current running scans, listen to their progress events
// and invoke cancellations or "done" signals. This allows throttling or canceling previous scans instead of
// having many scans running at once for the same files.
//
// The correct usage would be to create a NewScanProgress and call "go Listen()" to
// listen for cancel/done signals in the background.
// ScanProgress operations should be done in locked sections.
type ScanProgress struct {
	isDone bool
	done   chan bool
	cancel chan bool
	mutex  sync.Mutex
}

func NewScanProgress() *ScanProgress {
	return &ScanProgress{
		cancel: make(chan bool),
		done:   make(chan bool),
	}
}

func (rs *ScanProgress) GetDoneChannel() <-chan bool { return rs.done }

func (rs *ScanProgress) GetCancelChannel() <-chan bool { return rs.cancel }

// IsDone is true if the scan finished whether by cancellation or by a SetDone call
func (rs *ScanProgress) IsDone() bool {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	return rs.isDone
}

func (rs *ScanProgress) CancelScan() {
	log.Debug().Msg("Canceling scan")
	select {
	case <-time.After(timeout):
		// This should not happen if ScanProgress is used correctly and is here for safety.
		// Seeing this message in a log is a sign that something is wrong.
		// There should always be a goroutine that listens for this channel
		log.Warn().Str("method", "CancelScan").Msg("No listeners for cancel message - timing out")
		return
	case rs.cancel <- true:
		log.Debug().Msg("Cancel signal sent")
		rs.mutex.Lock()
		defer rs.mutex.Unlock()
		rs.isDone = true
	}
}

// SetDone will mark the ScanProgress as done and send a message to the "done" channel.
// It is safe to call SetDone repeatedly, or after CancelScan was called, so it's ok to
// defer a function that calls SetDone in a locked section.
func (rs *ScanProgress) SetDone() {
	rs.mutex.Lock()
	defer rs.mutex.Unlock()
	if rs.isDone {
		log.Debug().Msg("Scan progress is already done - returning without further action")
		return
	}
	rs.isDone = true
	select {
	case <-time.After(timeout):
		// This should not happen if ScanProgress is used correctly and is here for safety.
		// Seeing this message in a log is a sign that something is wrong.
		// There should always be a goroutine that listens for this channel
		log.Warn().Str("method", "SetDone").Msg("No listeners for Done message - timing out")
	case rs.done <- true:
		log.Debug().Msg("Done signal sent")
	}
}

// Listen waits for cancel or done signals until one of them is received.
// If the cancel signal is received, the cancel function will be called.
// Listen stops after the first signal is processed.
func (rs *ScanProgress) Listen(cancel context.CancelFunc, scanNumber int) {
	log.Debug().Msgf("Starting goroutine for scan %v", scanNumber)
	cancelChannel := rs.GetCancelChannel()
	doneChannel := rs.GetDoneChannel()
	select {
	case <-cancelChannel:
		log.Debug().Msgf("Canceling scan %v", scanNumber)
		cancel()
		return
	case <-doneChannel:
		log.Debug().Msgf("Scan %v is done", scanNumber)
		return
	}
}

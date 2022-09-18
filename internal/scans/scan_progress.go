package scans

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

const timeout = 5 * time.Second

// ScanProgress is a type that's used for tracking current running scans, listen to their progress events
// and invoke cancellations or "done" signals. This allows throttling or cancelling previous scans instead of
// having many scans running at once for the same files.
type ScanProgress struct {
	isDone bool
	done   chan struct{}
	cancel chan struct{}
}

func NewScanProgress() *ScanProgress {
	return &ScanProgress{
		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

func (rs *ScanProgress) GetDoneChannel() <-chan struct{}   { return rs.done }
func (rs *ScanProgress) GetCancelChannel() <-chan struct{} { return rs.cancel }
func (rs *ScanProgress) IsDone() bool                      { return rs.isDone }
func (rs *ScanProgress) CancelScan() {
	log.Debug().Msg("Cancelling scan")
	select {
	case <-time.After(timeout):
		log.Debug().Msg("No listeners for scan cancellation")
		return
	case rs.cancel <- struct{}{}:
		log.Debug().Msg("Cancel signal sent")
	}
}

func (rs *ScanProgress) SetDone() {
	rs.isDone = true
	select {
	case <-time.After(timeout):
		log.Debug().Msg("No listeners for Done message")
	case rs.done <- struct{}{}:
		log.Debug().Msg("Done signal sent")
	}
}

// Listen waits for cancel or done signals until one of them is received.
// If the cancel signal is received, the cancel function will be called
func (rs *ScanProgress) Listen(cancel context.CancelFunc, scanNumber int) {
	log.Debug().Msgf("Starting goroutine for scan %v", scanNumber)
	cancelChannel := rs.GetCancelChannel()
	doneChannel := rs.GetDoneChannel()
	select {
	case <-cancelChannel:
		log.Debug().Msgf("Cancelling scan %v", scanNumber)
		cancel()
		return
	case <-doneChannel:
		log.Debug().Msgf("Scan %v is done", scanNumber)
		return
	}
}

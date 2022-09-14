package scans

import (
	"context"

	"github.com/rs/zerolog/log"
)

// RunningScan is a type that's used for tracking current running scans, listen to their progress events
// and invoke cancellations or "done" signals. This allows throttling or cancelling previous scans instead of
// having many scans running at once for the same files.
type RunningScan struct {
	isDone bool
	done   chan struct{}
	cancel chan struct{}
}

func NewRunningScan() *RunningScan {
	return &RunningScan{
		cancel: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

func (rs *RunningScan) GetDoneChannel() <-chan struct{}   { return rs.done }
func (rs *RunningScan) GetCancelChannel() <-chan struct{} { return rs.cancel }
func (rs *RunningScan) IsDone() bool                      { return rs.isDone }
func (rs *RunningScan) CancelScan() {
	// Using select to send the signal without blocking when there are no listeners
	select {
	case rs.cancel <- struct{}{}:
	default: // If no one listening, do nothing
	}
}
func (rs *RunningScan) SetDone() {
	rs.isDone = true
	select {
	case rs.done <- struct{}{}: // If possible, send a done message
	default: // If there are no listeners, do nothing
	}
}

func (rs *RunningScan) Listen(cancel context.CancelFunc, i int) {
	log.Debug().Msgf("Starting goroutine for scan %v", i)
	select {
	case <-rs.GetCancelChannel():
		log.Debug().Msgf("Cancelling scan %v", i)
		cancel()
		return
	case <-rs.GetDoneChannel():
		log.Debug().Msgf("Scan %v is done", i)
		return
	}
}

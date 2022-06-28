package error_reporting

import (
	"github.com/rs/zerolog/log"
)

type testErrorReporter struct{}

func NewTestErrorReporter() ErrorReporter {
	return &testErrorReporter{}
}

func (s *testErrorReporter) FlushErrorReporting() {
}

func (s *testErrorReporter) CaptureError(err error) bool {
	log.Log().Err(err).Msg("An error has been captured by the testing error reporter")
	return true
}

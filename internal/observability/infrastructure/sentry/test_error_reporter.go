package sentry

import (
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
)

type testErrorReporter struct{}

func NewTestErrorReporter() error_reporting.ErrorReporter {
	return &testErrorReporter{}
}

func (s *testErrorReporter) FlushErrorReporting() {
}

func (s *testErrorReporter) CaptureError(err error) bool {
	log.Log().Err(err).Msg("An error has been captured by the testing error reporter")
	return true
}

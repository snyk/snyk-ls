package sentry

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

var target = NewSentryErrorReporter()

func TestErrorReporting_CaptureError(t *testing.T) {
	testutil.UnitTest(t)
	error := errors.New("test error")

	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := target.CaptureError(error)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = target.CaptureError(error)
	assert.True(t, captured)
}

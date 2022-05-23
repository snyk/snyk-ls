package error_reporting

import (
	"errors"
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/observability"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestErrorReporting_CaptureError(t *testing.T) {
	testutil.UnitTest(t)
	error := errors.New("test error")

	config.CurrentConfig().SetErrorReportingEnabled(false)
	captured := CaptureError(error)
	assert.False(t, captured)

	config.CurrentConfig().SetErrorReportingEnabled(true)
	captured = CaptureError(error)
	assert.True(t, captured)
}

func TestErrorReporting_Environment(t *testing.T) {
	testutil.UnitTest(t)
	config.Development = "true"
	curEnvironment := observability.Environment()
	assert.Equal(t, "development", curEnvironment)

	config.Development = "false"
	curEnvironment = observability.Environment()
	assert.Equal(t, "production", curEnvironment)
}

func TestErrorReporting_BeforeSend(t *testing.T) {
	testutil.UnitTest(t)
	testEvent := sentry.NewEvent()

	config.CurrentConfig().SetErrorReportingEnabled(true)
	result := observability.BeforeSend(testEvent, nil)
	assert.Equal(t, testEvent, result)

	config.CurrentConfig().SetErrorReportingEnabled(false)
	result = observability.BeforeSend(testEvent, nil)
	assert.Equal(t, (*sentry.Event)(nil), result)
}

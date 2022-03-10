package error_reporting

import (
	"errors"
	"testing"

	"github.com/snyk/snyk-ls/config"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
)

func TestErrorReporting_CaptureError(t *testing.T) {
	error := errors.New("Test error")

	config.IsErrorReportingEnabled = false
	captured := CaptureError(error)
	assert.False(t, captured)

	config.IsErrorReportingEnabled = true
	captured = CaptureError(error)
	assert.True(t, captured)
}

func TestErrorReporting_Environment(t *testing.T) {
	config.IsDevelopment = true
	curEnvironment := environment()
	assert.Equal(t, "development", curEnvironment)

	config.IsDevelopment = false
	curEnvironment = environment()
	assert.Equal(t, "production", curEnvironment)
}

func TestErrorReporting_BeforeSend(t *testing.T) {
	testEvent := sentry.NewEvent()

	config.IsErrorReportingEnabled = true
	result := beforeSend(testEvent, nil)
	assert.Equal(t, testEvent, result)

	config.IsErrorReportingEnabled = false
	result = beforeSend(testEvent, nil)
	assert.Equal(t, (*sentry.Event)(nil), result)
}

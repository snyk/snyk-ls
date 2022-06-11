package sentry

import (
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Sentry_Environment(t *testing.T) {
	testutil.UnitTest(t)
	config.Development = "true"
	curEnvironment := sentryEnvironment()
	assert.Equal(t, "development", curEnvironment)

	config.Development = "false"
	curEnvironment = sentryEnvironment()
	assert.Equal(t, "production", curEnvironment)
}

func Test_Sentry_BeforeSend(t *testing.T) {
	testutil.UnitTest(t)
	testEvent := sentry.NewEvent()

	config.CurrentConfig().SetErrorReportingEnabled(true)
	result := beforeSend(testEvent, nil)
	assert.Equal(t, testEvent, result)

	config.CurrentConfig().SetErrorReportingEnabled(false)
	result = beforeSend(testEvent, nil)
	assert.Equal(t, (*sentry.Event)(nil), result)
}

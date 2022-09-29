/*
 * Copyright 2022 Snyk Ltd.
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

package sentry

import (
	"testing"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
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

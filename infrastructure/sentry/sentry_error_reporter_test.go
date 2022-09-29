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

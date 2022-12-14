/*
 * © 2022 Snyk Limited All rights reserved.
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
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name         string
		expectedType string
		configValue  bool
	}{
		{name: "Telemetry Activated", expectedType: "*sentry.span", configValue: true},
		{name: "Telemetry Deactivated", expectedType: "*performance.NoopSpan", configValue: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testutil.UnitTest(t)
			config.CurrentConfig().SetTelemetryEnabled(test.configValue)
			i := gdprAwareSentryInstrumentor{}

			typeOf := reflect.TypeOf(i.CreateSpan("testTransaction", "testOperation")).String()

			assert.Equal(t, test.expectedType, typeOf)
		})
	}
}

func TestStartSpanCreatesAndStartsSpan(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTelemetryEnabled(false)
	i := &gdprAwareSentryInstrumentor{}

	span := i.StartSpan(context.Background(), "testOp").(*performance.NoopSpan)

	assert.Equal(t, span.Started, true)
	assert.Equal(t, span.Finished, false)
}

func TestNewTransaction(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTelemetryEnabled(false)
	i := &gdprAwareSentryInstrumentor{}

	span := i.NewTransaction(context.Background(), "testTransaction", "testOp").(*performance.NoopSpan)

	assert.Equal(t, span.Started, true)
	assert.Equal(t, span.Finished, false)
	assert.Equal(t, span.TxName != "", true)
}

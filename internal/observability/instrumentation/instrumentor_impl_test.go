package instrumentation

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name         string
		expectedType string
		configValue  bool
	}{
		{name: "Telemetry Activated", expectedType: "*instrumentation.sentrySpan", configValue: true},
		{name: "Telemetry Deactivated", expectedType: "*instrumentation.noopSpan", configValue: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testutil.UnitTest(t)
			config.CurrentConfig().SetTelemetryEnabled(test.configValue)
			i := InstrumentorImpl{}

			typeOf := reflect.TypeOf(i.CreateSpan(context.Background(), "testTransaction", "testOperation")).String()

			assert.Equal(t, test.expectedType, typeOf)
		})
	}
}

func TestStartSpanCreatesAndStartsSpan(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTelemetryEnabled(false)
	i := &InstrumentorImpl{}

	span := i.StartSpan(context.Background(), "testOp").(*noopSpan)

	assert.Equal(t, span.started, true)
	assert.Equal(t, span.finished, false)
}

func TestNewTransaction(t *testing.T) {
	testutil.UnitTest(t)
	config.CurrentConfig().SetTelemetryEnabled(false)
	i := &InstrumentorImpl{}

	span := i.NewTransaction(context.Background(), "testTransaction", "testOp").(*noopSpan)

	assert.Equal(t, span.started, false)
	assert.Equal(t, span.finished, false)
	assert.Equal(t, span.txName != "", true)
}

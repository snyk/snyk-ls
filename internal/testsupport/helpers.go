package testsupport

import (
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

const (
	IntegTestEnvVar = "INTEG_TESTS"
	SmokeTestEnvVar = "SMOKE_TESTS"
	NodejsGoof      = "https://github.com/snyk-labs/nodejs-goof"
	PythonGoof      = "https://github.com/JennySnyk/Python-goof"
)

func NotOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		t.Skipf("Not on windows, because %s", reason)
	}
}

func OnlyOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS != "windows" {
		t.Skipf("Only on windows, because %s", reason)
	}
}

func SetupEngineMock(t *testing.T) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	return mockEngine, engineConfig
}

func ReadMessageAssertNoWait[T any](t *testing.T, channel chan T) (msg T) {
	t.Helper()

	var ok bool
	select {
	case msg, ok = <-channel:
		if !ok {
			// Fatal failure (stop execution), as mishandled channels in Go can cause panics and infinite waits.
			assert.FailNow(t, "Expected a message, but the channel was closed")
		}
		return msg
	default:
		// Fatal failure (stop execution), as mishandled channels in Go can cause panics and infinite waits.
		assert.FailNow(t, "Expected a message, but no message was immediately available")
	}
	return msg // Unreachable
}

// Package testsupport contains test helpers for Snyk
package testsupport

import (
	"runtime"
	"testing"
)

const (
	IntegTestEnvVar = "INTEG_TESTS"
	SmokeTestEnvVar = "SMOKE_TESTS"
	NodejsGoof      = "https://github.com/snyk-labs/nodejs-goof"
	PythonGoof      = "https://github.com/JennySnyk/Python-goof"
	CppGoof         = "https://github.com/snyk-fixtures/cpp-goof"
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

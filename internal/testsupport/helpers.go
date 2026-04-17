// Package testsupport contains test helpers for Snyk
package testsupport

import (
	"os"
	"runtime"
	"testing"
)

const (
	IntegTestEnvVar = "INTEG_TESTS"
	SmokeTestEnvVar = "SMOKE_TESTS"
	// BenchmarkRealScanMonorepoEnvVar enables Test_SmokeRealScanMonorepoFixture alongside SMOKE_TESTS.
	// Default smoke runs skip that test so CI and local smoke stay fast; set to 1 to run the monorepo + mem measurement path.
	BenchmarkRealScanMonorepoEnvVar = "BENCHMARK_REAL_SCAN_MONOREPO"
	// BenchmarkRealScanMonorepoProfileDirEnvVar, when set to an existing or creatable directory, enables runtime/pprof CPU + heap profiles around the monorepo scan phase (Test and Benchmark).
	BenchmarkRealScanMonorepoProfileDirEnvVar = "BENCHMARK_REAL_SCAN_PROFILE_DIR"
	NodejsGoof                                = "https://github.com/snyk-labs/nodejs-goof"
	PythonGoof                                = "https://github.com/JennySnyk/Python-goof"
	CppGoof                                   = "https://github.com/snyk-fixtures/cpp-goof"
	CGoof                                     = "https://github.com/pilvikala/c-goof"
	FakeLeaks                                 = "https://github.com/leaktk/fake-leaks"
)

func NotOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "windows" {
		t.Skipf("Not on windows, because %s", reason)
	}
}

func NotOnMacOS(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == "darwin" {
		t.Skipf("Not on macOS, because %s", reason)
	}
}

func OnlyOnWindows(t *testing.T, reason string) {
	t.Helper()
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS != "windows" {
		t.Skipf("Only on windows, because %s", reason)
	}
}

// SkipUnlessBenchmarkRealScanMonorepo skips unless both SMOKE_TESTS and BENCHMARK_REAL_SCAN_MONOREPO are set.
// Use for heavy monorepo fixture + real Code/OSS scans that should not run on every smoke invocation.
func SkipUnlessBenchmarkRealScanMonorepo(t *testing.T) {
	t.Helper()
	if os.Getenv(SmokeTestEnvVar) == "" {
		t.Skipf("%s is not set", SmokeTestEnvVar)
	}
	if os.Getenv(BenchmarkRealScanMonorepoEnvVar) == "" {
		t.Skipf("set %s=1 to run the monorepo real-scan benchmark (requires %s=1)", BenchmarkRealScanMonorepoEnvVar, SmokeTestEnvVar)
	}
}

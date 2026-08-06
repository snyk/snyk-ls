/*
 * © 2022-2024 Snyk Limited
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

package authentication

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// countingErrorReporter records how often CaptureError is invoked so tests can assert
// that a canceled authentication is not reported as a failure.
type countingErrorReporter struct {
	captureErrorCalls int
}

func (r *countingErrorReporter) FlushErrorReporting() {}

func (r *countingErrorReporter) CaptureError(error) bool {
	r.captureErrorCalls++
	return true
}

func (r *countingErrorReporter) CaptureErrorAndReportAsIssue(types.FilePath, error) bool {
	r.captureErrorCalls++
	return true
}

var _ error_reporting.ErrorReporter = (*countingErrorReporter)(nil)

func TestCliAuthenticationProvider_AuthenticationMethod(t *testing.T) {
	p := &CliAuthenticationProvider{}
	assert.Equal(t, types.TokenAuthentication, p.AuthenticationMethod())
}

func assertCmd(t *testing.T, expectedArgs []string, actualCmd *exec.Cmd) {
	t.Helper()

	actualArgs := actualCmd.Args[1:]

	assert.Equal(t, expectedArgs, actualArgs)
}

func TestAuth_authCmd(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctx := t.Context()
	provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

	authCmd, err := provider.authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

func TestConfig_configGetAPICmd(t *testing.T) {
	engine := testutil.UnitTest(t)
	ctx := t.Context()
	provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

	configGetAPICmd, err := provider.configGetAPICmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"config", "get", "api"}, configGetAPICmd)
}

func TestSetAuthURLCmd(t *testing.T) {
	t.Run("works for the default endpoint", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

		var expectedURL = "https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works for a custom endpoint", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

		var expectedURL = "https://myOwnCompanyURL/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works when URL is in a substring", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

		var stringWithURL = "If auth does not automatically redirect you, copy this auth link: https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"
		var expectedURL = "https://app.snyk.io/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(stringWithURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("errors when there is a problem extracting the auth url", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

		var badURL = "https://invlidAuthURL.com"

		actualURL := provider.getAuthURL(badURL)

		assert.Equal(t, actualURL, "")
	})
}

func TestBuildCLICmd(t *testing.T) {
	t.Run("Insecure is respected", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		ctx := t.Context()
		resolver := testutil.DefaultConfigResolver(engine)
		provider := &CliAuthenticationProvider{engine: engine, configResolver: resolver}
		engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingProxyInsecure), true)

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Equal(t, resolver.GetString(types.SettingCliPath, nil), cmd.Args[0], "first arg should be CLI path")
		assert.Equal(t, "auth", cmd.Args[1])
		assert.Equal(t, "--insecure", cmd.Args[2])
	})

	t.Run("Api endpoint is respected", func(t *testing.T) {
		engine := testutil.UnitTest(t)
		ctx := t.Context()
		provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}
		config.UpdateApiEndpointsOnConfig(engine.GetConfiguration(), "https://api.eu.snyk.io")

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Contains(t, cmd.Env, "SNYK_API=https://api.eu.snyk.io")
	})
}

func TestRunCLICmd_Cancellation(t *testing.T) {
	engine := testutil.UnitTest(t)
	provider := &CliAuthenticationProvider{engine: engine, configResolver: testutil.DefaultConfigResolver(engine)}

	t.Run("returns the context error when canceled before running", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := provider.runCLICmd(ctx, exec.CommandContext(ctx, "sleep", "10"))

		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("normalizes 'signal: killed' to the context error when canceled mid-run", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("sleep subprocess kill semantics differ on Windows")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := exec.CommandContext(ctx, "sleep", "10")
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := provider.runCLICmd(ctx, cmd)

		// exec kills the subprocess and cmd.Run() returns "signal: killed"; runCLICmd must
		// normalize that into the context error so callers can detect the cancellation.
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotContains(t, err.Error(), "signal: killed")
	})
}

func TestAuthenticate_CanceledContext_NotReported(t *testing.T) {
	engine := testutil.UnitTest(t)
	reporter := &countingErrorReporter{}
	provider := NewCliAuthenticationProvider(engine, reporter, testutil.DefaultConfigResolver(engine))

	// A canceled context makes runCLICmd return context.Canceled before the CLI ever runs.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	token, err := provider.Authenticate(ctx)

	assert.Empty(t, token)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, reporter.captureErrorCalls, "a canceled authentication must not be reported")
}

// TestAuthenticate_GetTokenCanceled_NotReported covers the cancellation guard that fires after a
// successful `snyk auth` but during `snyk config get api` (getToken). A CLI stub exits instantly for
// `auth` and blocks for `config`, so the context can be canceled while only getToken is running.
func TestAuthenticate_GetTokenCanceled_NotReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script CLI stub is not portable to Windows")
	}
	engine := testutil.UnitTest(t)

	signalFile := filepath.Join(t.TempDir(), "gettoken-started")
	script := filepath.Join(t.TempDir(), "cli-stub.sh")
	// `auth` → exit 0 immediately; `config get api` → signal it started, then block so the test can
	// cancel while getToken (the second CLI call) is mid-run. `exec sleep` replaces the shell so
	// exec.CommandContext's kill lands on the sleep directly and cmd.Run() returns promptly on cancel
	// (a plain `sleep` would be an orphaned grandchild that keeps the stdout pipe open for its full
	// duration).
	scriptBody := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"config\" ]; then touch %q; exec sleep 30; fi\nexit 0\n", signalFile)
	require.NoError(t, os.WriteFile(script, []byte(scriptBody), 0o755))
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), script)

	reporter := &countingErrorReporter{}
	provider := NewCliAuthenticationProvider(engine, reporter, testutil.DefaultConfigResolver(engine))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		token string
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		tok, err := provider.Authenticate(ctx)
		resCh <- result{tok, err}
	}()

	// Cancel only once getToken's command has started — guarantees authenticate() already succeeded,
	// so the cancellation is observed by the getToken guard (cli_provider.go:72-76), not the first one.
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(signalFile)
		return statErr == nil
	}, 5*time.Second, 10*time.Millisecond, "getToken CLI command did not start")
	cancel()

	var res result
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Authenticate did not return after cancellation")
	}

	assert.Empty(t, res.token)
	assert.ErrorIs(t, res.err, context.Canceled)
	assert.Zero(t, reporter.captureErrorCalls, "a canceled getToken must not be reported")
}

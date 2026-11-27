/*
 * © 2026 Snyk Limited All rights reserved.
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

package iac

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/cli"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

const (
	helperExitCodeEnv = "SNYK_LS_IAC_TEST_HELPER_EXIT_CODE"
	helperBlockEnv    = "SNYK_LS_IAC_TEST_HELPER_BLOCK"
)

func Test_Scan_ExtensionExecutor_LegacyCliResult(t *testing.T) {
	exitedWith := func(code int) func(*testing.T) error {
		return func(t *testing.T) error {
			t.Helper()
			return exitErrorWithCode(t, code)
		}
	}

	tests := []struct {
		name        string
		stdout      string
		cliErr      func(*testing.T) error
		wantErrWith []string
	}{
		{name: "exit 0, empty output", stdout: ""},
		{name: "exit 0, whitespace output", stdout: "\n"},
		{name: "exit 1, empty output", stdout: "", cliErr: exitedWith(1), wantErrWith: []string{"no output", "exit status 1"}},
		{name: "exit 1, whitespace output", stdout: "\r\n", cliErr: exitedWith(1), wantErrWith: []string{"no output", "exit status 1"}},
		{name: "exit 1, JSON output", stdout: "[]", cliErr: exitedWith(1)},
		{name: "exit 2, empty output", stdout: "", cliErr: exitedWith(2), wantErrWith: []string{"exit status 2"}},
		{name: "killed process, empty output", stdout: "", cliErr: killedProcessError, wantErrWith: []string{"no output"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cliErr error
			if tt.cliErr != nil {
				cliErr = tt.cliErr(t)
			}

			issues, err := scanWithLegacyCliResult(t, []byte(tt.stdout), cliErr)

			if len(tt.wantErrWith) == 0 {
				require.NoError(t, err)
				assert.Empty(t, issues)
				return
			}
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "unmarshal")
			for _, want := range tt.wantErrWith {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

func scanWithLegacyCliResult(t *testing.T, stdout []byte, legacyCliErr error) ([]types.Issue, error) {
	t.Helper()
	engine := testutil.UnitTest(t)
	dir := t.TempDir()

	legacyCliID := workflow.NewWorkflowIdentifier("legacycli")
	_, err := engine.Register(legacyCliID, workflow.ConfigurationOptionsFromFlagset(&pflag.FlagSet{}), func(_ workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
		data := workflow.NewData(workflow.NewTypeIdentifier(legacyCliID, "stdout"), "application/json; schema=legacy-cli", stdout)
		return []workflow.Data{data}, legacyCliErr
	})
	require.NoError(t, err)

	resolver := defaultResolver(engine)
	scanner := New(engine.GetConfiguration(), engine.GetLogger(), performance.NewInstrumentor(), error_reporting.NewTestErrorReporter(engine), cli.NewExtensionExecutor(engine, resolver), resolver, testutil.NewDrainedProgressTracker())
	ctx := ctx2.NewContextWithFolderConfig(t.Context(), &types.FolderConfig{FolderPath: types.FilePath(dir)})

	return scanner.Scan(ctx, types.FilePath(dir))
}

func exitErrorWithCode(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_IacExit$")
	cmd.Env = append(os.Environ(), helperExitCodeEnv+"="+strconv.Itoa(code))
	err := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, code, exitErr.ExitCode())
	return err
}

func killedProcessError(t *testing.T) error {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_IacExit$")
	cmd.Env = append(os.Environ(), helperBlockEnv+"=1")
	require.NoError(t, cmd.Start())
	require.NoError(t, cmd.Process.Kill())
	err := cmd.Wait()
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	return err
}

func TestHelperProcess_IacExit(t *testing.T) {
	if os.Getenv(helperBlockEnv) != "" {
		time.Sleep(time.Minute)
		return
	}
	value := os.Getenv(helperExitCodeEnv)
	if value == "" {
		t.Skip("helper process")
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		os.Exit(255)
	}
	os.Exit(code)
}

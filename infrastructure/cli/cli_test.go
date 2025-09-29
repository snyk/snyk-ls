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

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

var pathListSep = string(os.PathListSeparator)

func Test_ExpandParametersFromConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	_, err := uuid.NewUUID()
	assert.NoError(t, err)
	settings := config.CliSettings{
		Insecure: true,
		C:        c,
	}
	c.SetCliSettings(&settings)
	var cmd = []string{"a", "b"}

	cmd = (&SnykCli{}).ExpandParametersFromConfig(cmd)

	assert.Contains(t, cmd, "a")
	assert.Contains(t, cmd, "b")
	assert.Contains(t, cmd, "--insecure")
	// --org is injected contextually in getCommand() based on working directory's folder config.
}

func Test_GetCommand_UsesConfigFiles(t *testing.T) {
	c := testutil.UnitTest(t)
	originalPathValue := "original_path" + pathListSep + "in_both_path"
	t.Setenv("PATH", originalPathValue)
	t.Setenv("TEST_VAR", "overrideable_value")

	// Create a temporary directory with a config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, ".snyk.env")
	configPathValue := "config" + pathListSep + "in_both_path"
	configContent := []byte("PATH=" + configPathValue + "\nTEST_VAR=test_value\n")
	err := os.WriteFile(configFile, configContent, 0660)
	require.NoError(t, err)

	// Set up CLI with custom config files
	cli := &SnykCli{c: c}
	c.Engine().GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{configFile})

	// Call getCommand which should load config files and prepare an isolated environment
	cmd, err := cli.getCommand([]string{"test", "command"}, types.FilePath(tempDir), t.Context())

	// Verify the command was created
	require.NoError(t, err)
	require.NotNil(t, cmd)
	assert.Equal(t, "test", cmd.Args[0])
	assert.Equal(t, "command", cmd.Args[1])

	// Verify environment variables were loaded from config file and correctly merged into cmd.Env
	assert.Contains(t, cmd.Env, "TEST_VAR=test_value")

	// Verify PATH was prepended (config path should come first)
	expectedPath := "config" + pathListSep + "in_both_path" + pathListSep + "original_path" // "in_both_path" is deduplicated, only "original_path" remains from original PATH
	assert.Contains(t, cmd.Env, "PATH="+expectedPath)
}

func Test_GetCommand_WaitsForEnvReadiness(t *testing.T) {
	c := testutil.UnitTest(t)

	// Create a test-controlled environment readiness channel
	testPrepareDefaultEnvChannel := make(chan bool)
	testPrepareDefaultEnvChannelClose := sync.OnceFunc(func() { close(testPrepareDefaultEnvChannel) })
	t.Cleanup(testPrepareDefaultEnvChannelClose)

	// Replace the ready channel with our test channel to simulate "not ready" state
	configValue := reflect.ValueOf(c).Elem()
	channelField := configValue.FieldByName("prepareDefaultEnvChannel")
	channelField = reflect.NewAt(channelField.Type(), unsafe.Pointer(channelField.UnsafeAddr())).Elem()
	channelField.Set(reflect.ValueOf(testPrepareDefaultEnvChannel))

	c.Engine().GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{})

	cli := &SnykCli{c: c}

	// Start building the command in a separate goroutine; it should block waiting on readiness
	started := make(chan bool, 1)
	t.Cleanup(func() { close(started) })
	unblocked := make(chan bool, 1)
	t.Cleanup(func() { close(unblocked) })
	var builtCmd *exec.Cmd
	var cmdErr error
	go func() {
		started <- true
		builtCmd, cmdErr = cli.getCommand([]string{"test"}, types.FilePath(t.TempDir()), t.Context())
		unblocked <- true
	}()

	// Wait until goroutine starts
	require.Eventually(t, func() bool {
		select {
		case <-started:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	// Verify it's blocked - should not complete for a reasonable time
	require.Never(t, func() bool {
		select {
		case <-unblocked:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond, "getCommand should block until environment is ready")

	// Now close the test channel to signal readiness
	testPrepareDefaultEnvChannelClose()

	// Verify it unblocks and completes
	require.Eventually(t, func() bool {
		select {
		case <-unblocked:
			return true
		default:
			return false
		}
	}, 2*time.Second, 10*time.Millisecond, "getCommand should complete after environment becomes ready")

	require.NoError(t, cmdErr)
	require.NotNil(t, builtCmd)
	assert.Contains(t, builtCmd.Args, "test")
}

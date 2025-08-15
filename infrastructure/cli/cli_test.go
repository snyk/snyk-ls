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
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_ExpandParametersFromConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	testOrg, err := uuid.NewUUID()
	assert.NoError(t, err)
	c.SetOrganization(testOrg.String())
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
	assert.Contains(t, cmd, "--org="+testOrg.String())
}

func Test_GetCommand_LoadsConfigFiles(t *testing.T) {
	c := testutil.UnitTest(t)
	originalPath := "original:path"
	t.Setenv("PATH", originalPath)
	t.Setenv("TEST_VAR", "overrideable_value")

	// Create a temporary directory with a config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, ".snyk.env")
	configContent := []byte("PATH=config:path\nTEST_VAR=test_value\n")
	err := os.WriteFile(configFile, configContent, 0660)
	assert.NoError(t, err)

	// Set up CLI with custom config files
	cli := &SnykCli{c: c}
	cloneConfig := c.Engine().GetConfiguration().Clone()
	cloneConfig.Set(configuration.CUSTOM_CONFIG_FILES, []string{configFile})

	// Mock the engine configuration to return our custom config files
	c.Engine().GetConfiguration().Set(configuration.CUSTOM_CONFIG_FILES, []string{configFile})

	// Call getCommand which should loads config files
	cmd := cli.getCommand([]string{"test", "command"}, types.FilePath(tempDir), t.Context())

	// Verify the command was created
	assert.NotNil(t, cmd)
	assert.Equal(t, "test", cmd.Args[0])
	assert.Equal(t, "command", cmd.Args[1])

	// Verify environment variable was loaded from config file
	assert.Equal(t, "test_value", os.Getenv("TEST_VAR"))

	// Verify PATH was prepended (config path should come first)
	currentPath := os.Getenv("PATH")
	expectedPath := "config:path:original" // "path" is deduplicated, only "original" remains from original PATH
	assert.Equal(t, expectedPath, currentPath,
		"PATH should be config path prepended with deduplication applied")
}

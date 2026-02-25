/*
 * © 2022-2026 Snyk Limited All rights reserved.
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

// Package testutil implements test setup functionality
package testutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/constants"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

func IntegTest(t *testing.T) *config.Config {
	t.Helper()
	return prepareTestHelper(t, testsupport.IntegTestEnvVar, "")
}

// TODO: remove useConsistentIgnores once we have fully rolled out the feature
func SmokeTest(t *testing.T, tokenSecretName string) *config.Config {
	t.Helper()
	return prepareTestHelper(t, testsupport.SmokeTestEnvVar, tokenSecretName)
}

func UnitTest(t *testing.T) *config.Config {
	t.Helper()
	c, _ := UnitTestWithCtx(t)
	return c
}

func UnitTestWithCtx(t *testing.T) (*config.Config, context.Context) {
	t.Helper()
	c := config.New(config.WithBinarySearchPaths([]string{}))
	err := c.WaitForDefaultEnv(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// we don't want server logging in test runs
	c.ConfigureLogging(nil)
	c.SetToken("00000000-0000-0000-0000-000000000001")
	c.SetTrustedFolderFeatureEnabled(false)
	c.SetAutomaticAuthentication(false)
	c.SetAuthenticationMethod(types.FakeAuthentication)
	redirectConfigAndDataHome(t, c)
	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t, c)
	// Set default org values to avoid API calls in tests
	// Use config method instead of setting it in GAF directly, to populate lastSetOrganization
	engineConfig := c.Engine().GetConfiguration()
	// Using Set() instead of AddDefaultValue() so tests can override with SetOrganization()
	c.SetOrganization("00000000-0000-0000-0000-000000000000")
	engineConfig.Set(configuration.ORGANIZATION_SLUG, "test-default-org-slug")
	engineConfig.Set(code.ConfigurationSastSettings, &sast_contract.SastResponse{SastEnabled: true, LocalCodeEngine: sast_contract.LocalCodeEngine{
		Enabled: false,
	},
	})
	t.Cleanup(func() {
		cleanupFakeCliFile(c)
		progress.CleanupChannels()
	})

	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepConfig: c,
	})
	ctx = ctx2.NewContextWithLogger(ctx, c.Logger())
	return c, ctx
}

func cleanupFakeCliFile(c *config.Config) {
	stat, err := os.Stat(c.CliSettings().Path())
	if err != nil {
		return
	}
	if stat.Size() < 1000 {
		// this is a fake CLI, removing it
		err = os.Remove(c.CliSettings().Path())
		if err != nil {
			c.Logger().Warn().Err(err).Msg("Failed to remove fake CLI")
		}
	}
}

func CLIDownloadLockFileCleanUp(t *testing.T, c *config.Config) {
	t.Helper()
	// remove lock file before test and after test
	lockFileName, _ := c.CLIDownloadLockFileName()
	file, _ := os.Open(lockFileName)
	_ = file.Close()
	_ = os.Remove(lockFileName)
	t.Cleanup(func() {
		_ = os.Remove(lockFileName)
	})
}

func CreateDummyProgressListener(t *testing.T) {
	t.Helper()
	var dummyProgressStopChannel = make(chan bool, 1)

	t.Cleanup(func() {
		dummyProgressStopChannel <- true
	})

	go func() {
		for {
			select {
			case <-progress.ToServerProgressChannel:
				continue
			case <-dummyProgressStopChannel:
				return
			}
		}
	}()
}

func prepareTestHelper(t *testing.T, envVar string, tokenSecretName string) *config.Config {
	t.Helper()
	if os.Getenv(envVar) == "" {
		t.Logf("%s is not set", envVar)
		t.SkipNow()
	}

	c := config.New(config.WithBinarySearchPaths([]string{}))
	err := c.WaitForDefaultEnv(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.ConfigureLogging(nil)
	token := testsupport.GetEnvironmentToken(tokenSecretName)
	c.SetToken(token)
	c.SetAuthenticationMethod(types.TokenAuthentication)
	c.SetAutomaticAuthentication(false)
	c.SetErrorReportingEnabled(false)
	c.SetTrustedFolderFeatureEnabled(false)
	c.SetIssueViewOptions(util.Ptr(types.NewIssueViewOptions(true, true)))
	redirectConfigAndDataHome(t, c)

	config.SetCurrentConfig(c)
	CLIDownloadLockFileCleanUp(t, c)
	t.Cleanup(func() {
		cleanupFakeCliFile(c)
	})
	return c
}

func redirectConfigAndDataHome(t *testing.T, c *config.Config) {
	t.Helper()
	conf := c.Engine().GetConfiguration()
	conf.Set(constants.DataHome, t.TempDir())
	storageFile := filepath.Join(t.TempDir(), "testStorage")
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.PersistInStorage(storedconfig.ConfigMainKey)
	conf.SetStorage(s)
}

func OnlyEnableCode(t *testing.T, c *config.Config) {
	t.Helper()
	c.SetSnykIacEnabled(false)
	c.SetSnykOssEnabled(false)
	c.SetSnykCodeEnabled(true)
	for _, folder := range c.Workspace().Folders() {
		folderConfig := c.FolderConfig(folder.Path())
		folderConfig.SastSettings = &sast_contract.SastResponse{
			SastEnabled: true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: false,
			},
			AutofixEnabled: true,
		}
		storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	}
}

// SetUpEngineMock creates and configures a mock GAF engine for testing.
// It sets up common expectations (GetConfiguration, GetLogger) and ensures the mock engine's
// configuration shares the same storage as the original config, allowing folder configurations
// to be persisted and read correctly across both objects.
// The mock engine is automatically set on the provided config.
func SetUpEngineMock(t *testing.T, c *config.Config) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()

	// Create mock engine and configuration
	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	// Set up the common expectation that GetConfiguration returns the configuration we just created
	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	// Set up the common expectation that GetLogger returns c's logger
	mockEngine.EXPECT().GetLogger().Return(c.Logger()).AnyTimes()

	// The new engineConfig needs to share the same storage as c's original engine config,
	// otherwise folder configs saved to engineConfig won't be visible to c.
	// Copy the storage setup from c's engine to the new engineConfig.
	originalConfig := c.Engine().GetConfiguration()
	engineConfig.Set(constants.DataHome, originalConfig.GetString(constants.DataHome))
	engineConfig.SetStorage(originalConfig.GetStorage())

	// Set the mock engine on the config provided
	c.SetEngine(mockEngine)

	return mockEngine, engineConfig
}

// WorkflowCapture holds the input data and config captured from a workflow invocation
type WorkflowCapture struct {
	Input  []workflow.Data
	Config configuration.Configuration
}

// MockAndCaptureWorkflowInvocation sets up a mock expectation to capture workflow invocations.
// It returns a channel that will receive the captured input data and config from each invocation.
// The channel is automatically closed via t.Cleanup().
func MockAndCaptureWorkflowInvocation(
	t *testing.T,
	mockEngine *mocks.MockEngine,
	workflowID workflow.Identifier,
	times int,
) chan WorkflowCapture {
	t.Helper()

	ch := make(chan WorkflowCapture, times)
	t.Cleanup(func() { close(ch) })

	mockEngine.EXPECT().InvokeWithInputAndConfig(workflowID, gomock.Any(), gomock.Any()).
		Times(times).
		Do(func(_ any, potentialWorkflowData any, potentialGAFConfig any) {
			workflowData, ok := potentialWorkflowData.([]workflow.Data)
			if !ok {
				t.Fatalf("Expected []workflow.Data as second argument to InvokeWithInputAndConfig, got %T", potentialWorkflowData)
				return
			}
			gafConfig, ok := potentialGAFConfig.(configuration.Configuration)
			if !ok {
				t.Fatalf("Expected configuration.Configuration as third argument to InvokeWithInputAndConfig, got %T", potentialGAFConfig)
				return
			}
			ch <- WorkflowCapture{Input: workflowData, Config: gafConfig}
		}).Return(nil, nil)

	return ch
}

// Enables SAST and AutoFix. Used in tests where scan results are provided by code.getSarifResponseJson2, and so we need
// enable AutoFix in order for the issues to get enhanced with commands (see code.addIssueActions).
func EnableSastAndAutoFix(c *config.Config) {
	c.Engine().GetConfiguration().Set(
		code.ConfigurationSastSettings,
		&sast_contract.SastResponse{SastEnabled: true, AutofixEnabled: true},
	)
}

func SkipLocally(t *testing.T) {
	t.Helper()
	ciVar := os.Getenv("CI")
	if ciVar == "" {
		t.Skip("not running in CI, skipping test")
	}
}

// SetupFoldersWithOrgs is a helper function for integration tests that sets up two folders
// with different organizations. It returns the folder paths, org UUIDs, and the config.
// The global org is set to a different value than the folder orgs to test isolation.
func SetupFoldersWithOrgs(t *testing.T, c *config.Config) (folderPath1, folderPath2 types.FilePath, globalOrg, folderOrg1, folderOrg2 string) {
	t.Helper()

	// Use valid UUIDs (hex characters only) to avoid API resolution issues in tests
	// These are valid UUIDs that won't trigger slug resolution
	globalOrg = "5b1ddf00-0000-0000-0000-000000000001"
	folderOrg1 = "5b1ddf00-0000-0000-0000-000000000002"
	folderOrg2 = "5b1ddf00-0000-0000-0000-000000000003"

	// Set a global org that is different from folder orgs
	c.SetOrganization(globalOrg)

	// Set up two folders with different orgs
	folderPath1 = types.FilePath(t.TempDir())
	folderPath2 = types.FilePath(t.TempDir())

	// Configure folder 1 with its own org
	folderConfig1 := &types.FolderConfig{
		FolderPath:                  folderPath1,
		PreferredOrg:                folderOrg1,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig1, c.Logger())
	require.NoError(t, err)

	// Configure folder 2 with a different org
	folderConfig2 := &types.FolderConfig{
		FolderPath:                  folderPath2,
		PreferredOrg:                folderOrg2,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig2, c.Logger())
	require.NoError(t, err)

	return folderPath1, folderPath2, globalOrg, folderOrg1, folderOrg2
}

// SetupFolderWithOrg is a helper function for integration tests that sets up a single folder
// with a specific organization. It returns the folder path, org UUID, and the config.
func SetupFolderWithOrg(t *testing.T, c *config.Config, orgUUID string) types.FilePath {
	t.Helper()

	folderPath := types.FilePath(t.TempDir())

	folderConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                orgUUID,
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err := storedconfig.UpdateFolderConfig(c.Engine().GetConfiguration(), folderConfig, c.Logger())
	require.NoError(t, err)

	return folderPath
}

// SetupGlobalOrgOnly is a helper function for integration tests that sets up only a global org
// (no folder-specific org). It returns a test folder path and the global org UUID.
func SetupGlobalOrgOnly(t *testing.T, c *config.Config) (folderPath types.FilePath, globalOrg string) {
	t.Helper()

	globalOrg = "00000000-0000-0000-0000-000000000004"
	c.SetOrganization(globalOrg)

	folderPath = types.FilePath(t.TempDir())

	return folderPath, globalOrg
}

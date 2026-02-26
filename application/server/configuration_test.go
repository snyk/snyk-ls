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

package server

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	mock_command "github.com/snyk/snyk-ls/domain/ide/command/mock"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/analytics"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

var sampleSettings = types.Settings{
	ActivateSnykOpenSource:     "false",
	ActivateSnykCode:           "false",
	ActivateSnykIac:            "false",
	Insecure:                   "true",
	Endpoint:                   "https://api.fake.snyk.io",
	AdditionalParams:           "--all-projects -d",
	AdditionalEnv:              "a=b;c=d",
	Path:                       "addPath",
	SendErrorReports:           "true",
	Token:                      "token",
	SnykCodeApi:                "https://deeproxy.fake.snyk.io",
	EnableSnykLearnCodeActions: "true",
}

func keyFoundInEnv(key string) bool {
	found := false
	env := os.Environ()
	for _, v := range env {
		if strings.HasPrefix(v, key+"=") {
			found = true
			break
		}
	}
	return found
}

func Test_WorkspaceDidChangeConfiguration_Push(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)
	loc, _ := setupServer(t, c)

	// Wait for default environment to be ready before testing PATH updates
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := c.WaitForDefaultEnv(ctx)
	if err != nil {
		t.Fatal(err, "error waiting for default environment")
	}

	t.Setenv("a", "")
	t.Setenv("c", "")
	params := types.DidChangeConfigurationParams{Settings: sampleSettings}
	_, err = loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.True(t, c.CliSettings().Insecure)
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
	assert.Equal(t, params.Settings.Endpoint, c.SnykApi())
	assert.Equal(t, params.Settings.Endpoint, conf.GetString(configuration.API_URL))
	assert.Equal(t, "b", os.Getenv("a"))
	assert.Equal(t, "d", os.Getenv("c"))
	assert.True(t, strings.Contains(os.Getenv("PATH"), "addPath"))
	assert.True(t, c.IsErrorReportingEnabled())
	assert.Equal(t, "token", c.Token())
	assert.Equal(t, sampleSettings.EnableSnykLearnCodeActions, strconv.FormatBool(c.IsSnykLearnCodeActionsEnabled()))
}

func Test_WorkspaceDidChangeConfiguration_Pull(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, _ := setupCustomServer(t, c, callBackMock)

	_, err := loc.Client.Call(ctx, "initialize", types.InitializeParams{
		Capabilities: types.ClientCapabilities{
			Workspace: types.WorkspaceClientCapabilities{
				Configuration: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	params := types.DidChangeConfigurationParams{Settings: types.Settings{}}
	_, err = loc.Client.Call(t.Context(), "workspace/didChangeConfiguration", params)
	if err != nil {
		t.Fatal(err, "error calling server")
	}
	assert.NoError(t, err)

	conf := c.Engine().GetConfiguration()
	assert.Equal(t, false, c.IsSnykCodeEnabled())
	assert.Equal(t, false, c.IsSnykOssEnabled())
	assert.Equal(t, false, c.IsSnykIacEnabled())
	assert.True(t, c.CliSettings().Insecure)
	assert.True(t, conf.GetBool(configuration.INSECURE_HTTPS))
	assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
	assert.Equal(t, sampleSettings.Endpoint, c.SnykApi())
	assert.Equal(t, c.SnykApi(), conf.GetString(configuration.API_URL))
	assert.True(t, c.IsErrorReportingEnabled())
	assert.Equal(t, "token", c.Token())
	assert.Equal(t, sampleSettings.EnableSnykLearnCodeActions, strconv.FormatBool(c.IsSnykLearnCodeActionsEnabled()))
}

func callBackMock(_ context.Context, request *jrpc2.Request) (any, error) {
	if request.Method() == "workspace/configuration" {
		return []types.Settings{sampleSettings}, nil
	}
	return nil, nil
}

func Test_WorkspaceDidChangeConfiguration_PullNoCapability(t *testing.T) {
	c := testutil.UnitTest(t)
	loc, jsonRPCRecorder := setupCustomServer(t, c, callBackMock)

	params := types.DidChangeConfigurationParams{Settings: types.Settings{}}
	var updated = true
	err := loc.Client.CallResult(t.Context(), "workspace/didChangeConfiguration", params, &updated)
	if err != nil {
		t.Fatal(err, "error calling server")
	}

	assert.NoError(t, err)
	assert.False(t, updated)
	assert.Eventually(t, func() bool {
		return len(jsonRPCRecorder.Callbacks()) == 0
	}, time.Second, time.Millisecond)
}

func Test_UpdateSettings(t *testing.T) {
	orgUuid, _ := uuid.NewRandom()
	expectedOrgId := orgUuid.String()

	t.Run("All settings are updated", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		tempDir1 := filepath.Join(t.TempDir(), "tempDir1")
		tempDir2 := filepath.Join(t.TempDir(), "tempDir2")
		nonDefaultSeverityFilter := types.NewSeverityFilter(false, true, false, true)
		nonDefaultIssueViewOptions := types.NewIssueViewOptions(false, true)
		hoverVerbosity := 1
		outputFormat := "html"
		settings := types.Settings{
			ActivateSnykOpenSource:       "false",
			ActivateSnykCode:             "false",
			ActivateSnykIac:              "false",
			Insecure:                     "true",
			Endpoint:                     "https://api.snyk.io",
			AdditionalParams:             "--all-projects -d",
			AdditionalEnv:                "a=b;c=d",
			Path:                         "addPath",
			SendErrorReports:             "true",
			Organization:                 &expectedOrgId,
			ManageBinariesAutomatically:  "false",
			CliPath:                      filepath.Join(t.TempDir(), "cli"),
			Token:                        "a fancy token",
			FilterSeverity:               &nonDefaultSeverityFilter,
			IssueViewOptions:             &nonDefaultIssueViewOptions,
			TrustedFolders:               []string{"trustedPath1", "trustedPath2"},
			OsPlatform:                   "windows",
			OsArch:                       "amd64",
			RuntimeName:                  "java",
			RuntimeVersion:               "1.8.0_275",
			ScanningMode:                 "manual",
			AuthenticationMethod:         types.FakeAuthentication,
			EnableSnykOpenBrowserActions: "true",
			HoverVerbosity:               &hoverVerbosity, // default is 3
			OutputFormat:                 &outputFormat,   // default is markdown
			FolderConfigs: []types.LspFolderConfig{
				{
					FolderPath:           types.FilePath(tempDir1),
					BaseBranch:           util.Ptr("testBaseBranch1"),
					AdditionalParameters: []string{"--file=asdf"},
				},
				{
					FolderPath: types.FilePath(tempDir2),
					BaseBranch: util.Ptr("testBaseBranch2"),
				},
			},
		}

		err := initTestRepo(t, tempDir1)
		assert.NoError(t, err)

		err = initTestRepo(t, tempDir2)
		assert.NoError(t, err)

		UpdateSettings(c, settings, analytics.TriggerSourceTest)

		assert.Equal(t, false, c.IsSnykCodeEnabled())
		assert.Equal(t, false, c.IsSnykOssEnabled())
		assert.Equal(t, false, c.IsSnykIacEnabled())
		assert.Equal(t, true, c.CliSettings().Insecure)
		assert.Equal(t, []string{"--all-projects", "-d"}, c.CliSettings().AdditionalOssParameters)
		assert.Equal(t, "https://api.snyk.io", c.SnykApi())
		assert.Equal(t, "b", os.Getenv("a"))
		assert.Equal(t, "d", os.Getenv("c"))
		assert.True(t, strings.HasPrefix(os.Getenv("PATH"), "addPath"+string(os.PathListSeparator)))
		assert.True(t, c.IsErrorReportingEnabled())
		// Organization is set globally but may be cleared at folder level by LDX-Sync logic
		// when it matches the global org and is not the default
		assert.Equal(t, expectedOrgId, c.Organization())
		assert.False(t, c.ManageBinariesAutomatically())
		assert.Equal(t, settings.CliPath, c.CliSettings().Path())
		assert.Equal(t, nonDefaultSeverityFilter, c.FilterSeverity())
		assert.Equal(t, nonDefaultIssueViewOptions, c.IssueViewOptions())
		assert.Subset(t, []types.FilePath{"trustedPath1", "trustedPath2"}, c.TrustedFolders())
		assert.Equal(t, settings.OsPlatform, c.OsPlatform())
		assert.Equal(t, settings.OsArch, c.OsArch())
		assert.Equal(t, settings.RuntimeName, c.RuntimeName())
		assert.Equal(t, settings.RuntimeVersion, c.RuntimeVersion())
		assert.False(t, c.IsAutoScanEnabled())
		assert.Equal(t, true, c.IsSnykOpenBrowserActionEnabled())
		assert.Equal(t, *settings.HoverVerbosity, c.HoverVerbosity())
		assert.Equal(t, *settings.OutputFormat, c.Format())

		folderConfig1 := c.FolderConfig(types.FilePath(tempDir1))
		assert.NotEmpty(t, folderConfig1.BaseBranch)
		// AdditionalParameters are preserved through the update
		if len(folderConfig1.AdditionalParameters) > 0 {
			assert.Equal(t, settings.FolderConfigs[0].AdditionalParameters[0],
				folderConfig1.AdditionalParameters[0])
		}
		// Since the incoming folderConfig doesn't have OrgSetByUser/OrgMigratedFromGlobalConfig set,
		// folderConfigsOrgSettingsEqual returns false, triggering UpdateFolderConfigOrg.
		// UpdateFolderConfigOrg will migrate the config and set the org based on LDX-Sync logic.
		// The migration flag should be set after the update.
		assert.True(t, folderConfig1.OrgMigratedFromGlobalConfig, "Should be migrated after update")

		folderConfig2 := c.FolderConfig(types.FilePath(tempDir2))
		assert.NotEmpty(t, folderConfig2.BaseBranch)
		assert.Empty(t, folderConfig2.AdditionalParameters)
		// Same logic applies to folder2
		assert.True(t, folderConfig2.OrgMigratedFromGlobalConfig, "Should be migrated after update")

		assert.Eventually(t, func() bool { return c.Token() == "a fancy token" }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		UpdateSettings(c, types.Settings{}, analytics.TriggerSourceTest)

		assert.Equal(t, 3, c.HoverVerbosity())
		assert.Equal(t, c.Format(), config.FormatMd)
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a="}, analytics.TriggerSourceTest)

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)
		varCount := len(os.Environ())

		UpdateSettings(c, types.Settings{AdditionalEnv: " "}, analytics.TriggerSourceTest)

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a=; b"}, analytics.TriggerSourceTest)

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		c := testutil.UnitTest(t)
		di.TestInit(t)

		// Use platform-appropriate paths
		path1 := filepath.Join("a", "b")
		path2 := filepath.Join("b", "c")
		UpdateSettings(c, types.Settings{TrustedFolders: []string{path1, path2}}, analytics.TriggerSourceTest)

		assert.Contains(t, c.TrustedFolders(), types.FilePath(path1))
		assert.Contains(t, c.TrustedFolders(), types.FilePath(path2))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			}, analytics.TriggerSourceTest)

			assert.True(t, c.ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "false",
			}, analytics.TriggerSourceTest)

			assert.False(t, c.ManageBinariesAutomatically())
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			}, analytics.TriggerSourceTest)

			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "dog",
			}, analytics.TriggerSourceTest)

			assert.True(t, c.ManageBinariesAutomatically())
		})
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{ActivateSnykCodeSecurity: "true"}, analytics.TriggerSourceTest)

		assert.True(t, c.IsSnykCodeEnabled(), "ActivateSnykCodeSecurity should enable Snyk Code")
	})
	t.Run("activateSnykCode and activateSnykCodeSecurity are ORed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{
			ActivateSnykCode:         "false",
			ActivateSnykCodeSecurity: "true",
		}, analytics.TriggerSourceTest)

		assert.True(t, c.IsSnykCodeEnabled(), "Should be enabled when either flag is true")
	})
	t.Run("activateSnykCode alone enables SnykCode", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{
			ActivateSnykCode: "true",
		}, analytics.TriggerSourceTest)

		assert.True(t, c.IsSnykCodeEnabled())
	})
	t.Run("neither activateSnykCode nor activateSnykCodeSecurity disables SnykCode", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{
			ActivateSnykCode:         "false",
			ActivateSnykCodeSecurity: "false",
		}, analytics.TriggerSourceTest)

		assert.False(t, c.IsSnykCodeEnabled())
	})

	t.Run("severity filter", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter}, analytics.TriggerSourceTest)

			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &emptyLikeSeverityFilter}, analytics.TriggerSourceTest)

			assert.Equal(t, emptyLikeSeverityFilter, c.FilterSeverity())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter}, analytics.TriggerSourceTest)
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())

			UpdateSettings(c, types.Settings{}, analytics.TriggerSourceTest)
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions}, analytics.TriggerSourceTest)

			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(c, types.Settings{IssueViewOptions: &emptyLikeIssueViewOptions}, analytics.TriggerSourceTest)

			assert.Equal(t, emptyLikeIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions}, analytics.TriggerSourceTest)
			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())

			UpdateSettings(c, types.Settings{}, analytics.TriggerSourceTest)
			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())
		})
	})
}

func initTestRepo(t *testing.T, tempDir string) error {
	t.Helper()
	repo1, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)
	absoluteFileName := filepath.Join(tempDir, "testFile")
	err = os.WriteFile(absoluteFileName, []byte("testData"), 0600)
	assert.NoError(t, err)
	worktree, err := repo1.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Add(filepath.Base(absoluteFileName))
	assert.NoError(t, err)
	_, err = worktree.Commit("testCommit", &git.CommitOptions{
		Author: &object.Signature{Name: t.Name()},
	})
	assert.NoError(t, err)
	return err
}

func Test_UpdateSettings_BlankOrganizationResetsToDefault_Integration(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	c.SetOrganization(initialOrgId)
	require.Equal(t, initialOrgId, c.Organization(), "org should be set to the value we just set it to")

	// Set to empty string to reset to the user's preferred default org they defined in the web UI.
	updateOrganization(c, types.Settings{Organization: util.Ptr("")}, analytics.TriggerSourceTest)

	// Verify it's not the initial org or empty string.
	actualOrgAfterBlank := c.Organization()
	assert.NotEqual(t, initialOrgId, actualOrgAfterBlank, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrgAfterBlank, "org should have resolved to the user's preferred default org they defined in the web UI")

	// Verify it's a valid UUID (preferred orgs are always UUIDs).
	_, err := uuid.Parse(actualOrgAfterBlank)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

func Test_UpdateSettings_WhitespaceOrganizationResetsToDefault_Integration(t *testing.T) {
	c := testutil.IntegTest(t)

	// Set to a specific org first
	initialOrgId := "00000000-0000-0000-0000-000000000001"
	c.SetOrganization(initialOrgId)
	require.Equal(t, initialOrgId, c.Organization(), "org should be set to the value we just set it to")

	// Set to whitespace to reset to the user's preferred default org they defined in the web UI.
	// Whitespace should be trimmed to empty string.
	updateOrganization(c, types.Settings{Organization: util.Ptr(" ")}, analytics.TriggerSourceTest)

	// Verify it's not the initial org or empty string.
	actualOrgAfterWhitespace := c.Organization()
	assert.NotEqual(t, initialOrgId, actualOrgAfterWhitespace, "org should have changed from initial value")
	assert.NotEmpty(t, actualOrgAfterWhitespace, "org should have resolved to the user's preferred default org they defined in the web UI")

	// Verify it's a valid UUID (preferred orgs are always UUIDs).
	_, err := uuid.Parse(actualOrgAfterWhitespace)
	assert.NoError(t, err, "resolved org should be a valid UUID")
}

// Common test setup for updateFolderConfig tests
type folderConfigTestSetup struct {
	t            *testing.T
	c            *config.Config
	engineConfig configuration.Configuration
	logger       *zerolog.Logger
	folderPath   types.FilePath
}

func setupFolderConfigTest(t *testing.T) *folderConfigTestSetup {
	t.Helper()
	c := testutil.UnitTest(t)
	di.TestInit(t)

	engineConfig := c.Engine().GetConfiguration()

	// Register mock default value functions for org config to avoid API calls in tests
	engineConfig.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("test-default-org-uuid"))
	engineConfig.AddDefaultValue(configuration.ORGANIZATION_SLUG, configuration.ImmutableDefaultValueFunction("test-default-org-slug"))

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	logger := c.Logger()

	return &folderConfigTestSetup{
		t:            t,
		c:            c,
		engineConfig: engineConfig,
		logger:       logger,
		folderPath:   folderPath,
	}
}

func (s *folderConfigTestSetup) createStoredConfig(org string, migrated bool, userSet bool) {
	storedConfig := &types.FolderConfig{
		FolderPath:                  s.folderPath,
		PreferredOrg:                org,
		OrgMigratedFromGlobalConfig: migrated,
		OrgSetByUser:                userSet,
	}
	err := storedconfig.UpdateFolderConfig(s.engineConfig, storedConfig, s.logger)
	require.NoError(s.t, err)
}

func (s *folderConfigTestSetup) callUpdateFolderConfig(org string) {
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   s.folderPath,
				PreferredOrg: &org,
			},
		},
	}
	updateFolderConfig(s.c, settings, s.logger, analytics.TriggerSourceTest)
}

func (s *folderConfigTestSetup) getUpdatedConfig() *types.FolderConfig {
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(s.engineConfig, s.folderPath, s.logger)
	require.NoError(s.t, err)
	return updatedConfig
}

// setupMigratedConfigInheritingFromBlankGlobal sets up the test scenario where
// a migrated config inherits from a blank global organization
func (s *folderConfigTestSetup) setupMigratedConfigInheritingFromBlankGlobal() {
	// Setup stored config with empty org, migrated flag set to true, and userSet to false
	s.createStoredConfig("", true, false)

	// Set global organization to empty
	s.c.SetOrganization("")

	// Call updateFolderConfig with empty org
	s.callUpdateFolderConfig("")
}

// setupNotMigratedLdxSyncReturnsDifferentOrg sets up the test scenario where
// a non-migrated config has LDX-Sync return a different organization
func (s *folderConfigTestSetup) setupNotMigratedLdxSyncReturnsDifferentOrg() {
	// Setup stored config without migration flag, with initial org, and userSet to false
	s.createStoredConfig("initial-org", false, false)

	// Set global organization
	s.c.SetOrganization("global-org-id")
}

// setupMigratedConfigUserSetButInheritingFromBlank sets up the test scenario where
// a migrated config was previously user-set but now inherits from blank global
func (s *folderConfigTestSetup) setupMigratedConfigUserSetButInheritingFromBlank() {
	// Setup stored config with empty org, migrated flag set to true, and userSet to true
	s.createStoredConfig("", true, true)

	// Set global organization to empty
	s.c.SetOrganization("")
}

// Test scenarios for updateFolderConfig with LDX-Sync integration
func Test_updateFolderConfig_MigratedConfig_UserSetWithNonEmptyOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup stored config with user-set org
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                "user-org-id",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	c.SetOrganization("global-org-id")

	// Call updateFolderConfig with the folder config
	userOrgID := "user-org-id"
	settings := types.Settings{
		Organization: util.Ptr("global-org-id"), // Include settings.Organization for the condition check
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: &userOrgID,
			},
		},
	}
	updateFolderConfig(c, settings, logger, analytics.TriggerSourceTest)

	// Verify the org was kept - with the current implementation, UpdateFolderConfigOrg is always called
	// due to pointer comparison, but the org should remain the same since it's user-set
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Equal(t, "user-org-id", updatedConfig.PreferredOrg, "PreferredOrg should remain as user-set value")
	// Note: OrgSetByUser behavior depends on UpdateFolderConfigOrg logic when org hasn't actually changed
}

func Test_updateFolderConfig_MigratedConfig_InheritingFromBlankGlobal(t *testing.T) {
	t.Skip("Test uses old logic") // TODO - Fix or scrap this test.
	setup := setupFolderConfigTest(t)

	// Setup the test scenario
	setup.setupMigratedConfigInheritingFromBlankGlobal()

	// Create settings and call updateFolderConfig
	emptyOrg := ""
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &emptyOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: When both folder and global org are empty and LDX-Sync is called
	updatedConfig := setup.getUpdatedConfig()
	// LDX-Sync will attempt to resolve the org
	assert.False(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be false")
}

func Test_updateFolderConfig_NotMigrated_EmptyStoredOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config without migration flag and empty org
	setup.createStoredConfig("", false, false)
	setup.c.SetOrganization("global-org-id")
	folderPath := setup.folderPath

	// Call updateFolderConfig
	// Note: Since folderConfig doesn't have OrgMigratedFromGlobalConfig set,
	// folderConfigsOrgSettingsEqual will return false, triggering UpdateFolderConfigOrg
	setup.callUpdateFolderConfig("")
	emptyOrg := ""
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: &emptyOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify UpdateFolderConfigOrg was called and set the migration flag
	updatedConfig := setup.getUpdatedConfig()
	// After migration, the flag should be set
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true after migration")
}

func Test_updateFolderConfig_NotMigrated_LdxSyncReturnsDifferentOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup the test scenario
	setup.setupNotMigratedLdxSyncReturnsDifferentOrg()

	// Call updateFolderConfig
	// Note: Since folderConfig doesn't have OrgMigratedFromGlobalConfig set,
	// folderConfigsOrgSettingsEqual will return false, triggering UpdateFolderConfigOrg
	initialOrg := "initial-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &initialOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify UpdateFolderConfigOrg was called and set the migration flag
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true after migration")
}

func Test_updateFolderConfig_MigratedConfig_UserSetButInheritingFromBlank(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup the test scenario
	setup.setupMigratedConfigUserSetButInheritingFromBlank()

	// Call updateFolderConfig with empty org settings
	emptyOrg := ""
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &emptyOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
	// This test specifically checks the case where both folder and global orgs are empty
	updatedConfig := setup.getUpdatedConfig()
	// When LDX-Sync is called, OrgSetByUser behavior depends on the result
	assert.Empty(t, updatedConfig.PreferredOrg, "PreferredOrg should remain empty when inheriting from blank global")
}

// Test that UpdateFolderConfigOrg is skipped when config is unchanged and global org hasn't changed
func Test_updateFolderConfig_SkipsUpdateWhenConfigUnchanged(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	require.NoError(t, err)

	// Setup stored config
	engineConfig := c.Engine().GetConfiguration()
	logger := c.Logger()
	storedConfig := &types.FolderConfig{
		FolderPath:                  folderPath,
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}
	err = storedconfig.UpdateFolderConfig(engineConfig, storedConfig, logger)
	require.NoError(t, err)

	c.SetOrganization("test-org")

	// Call updateFolderConfig with exact same config and same global org
	// DeepEqual should return true, so UpdateFolderConfigOrg should be skipped
	testOrg := "test-org"
	settings := types.Settings{
		Organization: util.Ptr("test-org"),
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: &testOrg,
			},
		},
	}
	updateFolderConfig(c, settings, logger, analytics.TriggerSourceTest)

	// Verify config remains unchanged (UpdateFolderConfigOrg was skipped)
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Equal(t, "test-org", updatedConfig.PreferredOrg)
	assert.True(t, updatedConfig.OrgSetByUser, "Should remain true since UpdateFolderConfigOrg was skipped")
}

func Test_updateFolderConfig_HandlesNilStoredConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	// Use a non-existent path that might return nil
	folderPath := types.FilePath("/non/existent/path")
	logger := c.Logger()

	c.SetOrganization("test-org")

	// Call updateFolderConfig with a folder that doesn't exist
	testOrg := "test-org"
	settings := types.Settings{
		Organization: util.Ptr("test-org"),
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: &testOrg,
			},
		},
	}

	// Should not panic and should handle nil gracefully
	updateFolderConfig(c, settings, logger, analytics.TriggerSourceTest)
	// If we get here without panic, the nil check worked
}

func Test_InitializeSettings(t *testing.T) {
	di.TestInit(t)

	t.Run("device ID is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := "test-device-id"

		InitializeSettings(c, types.Settings{DeviceId: deviceId})

		assert.Equal(t, deviceId, c.DeviceID())
	})

	t.Run("device ID is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)
		deviceId := c.DeviceID()

		InitializeSettings(c, types.Settings{})

		assert.Equal(t, deviceId, c.DeviceID())
	})

	t.Run("activateSnykCodeSecurity enables SnykCode via OR on init", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.Settings{ActivateSnykCodeSecurity: "true"})

		assert.True(t, c.IsSnykCodeEnabled(), "ActivateSnykCodeSecurity should enable Snyk Code on init")
	})
	t.Run("activateSnykCodeSecurity not passed does not enable SnykCode on init", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.Settings{})

		assert.False(t, c.IsSnykCodeEnabled())
	})

	t.Run("custom path configuration", func(t *testing.T) {
		c := testutil.UnitTest(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		// update path to hold a custom value
		UpdateSettings(c, types.Settings{Path: first}, analytics.TriggerSourceTest)
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		// update path to hold another value
		UpdateSettings(c, types.Settings{Path: second}, analytics.TriggerSourceTest)
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path with non-empty settings
		UpdateSettings(c, types.Settings{Path: "", AuthenticationMethod: "token"}, analytics.TriggerSourceTest)
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), second))

		assert.True(t, keyFoundInEnv(upperCasePathKey))
		assert.False(t, keyFoundInEnv(caseSensitivePathKey))
	})
}

// Test: Mainly tests deleting AutoDeterminedOrg does not forget it.
func Test_updateFolderConfig_MigratedConfig_AutoMode_EmptyOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config with migration flag set, userSet false, empty org, and AutoDeterminedOrg set
	engineConfig := setup.c.Engine().GetConfiguration()
	storedConfig := &types.FolderConfig{
		FolderPath:                  setup.folderPath,
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
		AutoDeterminedOrg:           "existing-auto-org",
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, setup.logger)
	require.NoError(t, err)

	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig with empty org (should stay in auto mode)
	// Since org settings are equal, updateFolderConfigOrg won't be called
	emptyOrg := ""
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &emptyOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: PreferredOrg should remain empty (auto mode), AutoDeterminedOrg should be preserved
	updatedConfig := setup.getUpdatedConfig()
	assert.Empty(t, updatedConfig.PreferredOrg, "PreferredOrg should remain empty in auto mode")
	assert.False(t, updatedConfig.OrgSetByUser, "OrgSetByUser should remain false in auto mode")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
	assert.NotEmpty(t, updatedConfig.AutoDeterminedOrg, "AutoDeterminedOrg should be preserved")
}

// This is an edge case where a migrated config has a non-empty org but is not user-set
func Test_updateFolderConfig_MigratedConfig_AutoMode_NonEmptyOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config with migration flag set, userSet false, but has an org
	engineConfig := setup.c.Engine().GetConfiguration()
	storedConfig := &types.FolderConfig{
		FolderPath:                  setup.folderPath,
		PreferredOrg:                "old-auto-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
		AutoDeterminedOrg:           "auto-org-id",
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, setup.logger)
	require.NoError(t, err)

	setup.c.SetOrganization("global-org-id")

	differentOrg := "different-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &differentOrg, // Different from stored
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: We correctly set it as org set by user.
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "different-org", updatedConfig.PreferredOrg, "PreferredOrg should be the new org")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true when org changes")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
	assert.NotEmpty(t, updatedConfig.AutoDeterminedOrg, "AutoDeterminedOrg should be set")
}

// Test: Org change detection when PreferredOrg changes for migrated configs
func Test_updateFolderConfig_MigratedConfig_OrgChangeDetection(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup mock LdxSyncService to verify it's called
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLdxSyncService := mock_command.NewMockLdxSyncService(ctrl)
	originalService := di.LdxSyncService()
	di.SetLdxSyncService(mockLdxSyncService)
	defer di.SetLdxSyncService(originalService)

	// Add folder to workspace so GetFolderContaining can find it
	folder := workspace.NewFolder(
		setup.c,
		setup.folderPath,
		"test-folder",
		nil,
		di.HoverService(),
		di.ScanNotifier(),
		di.Notifier(),
		di.ScanPersister(),
		di.ScanStateAggregator(),
		di.FeatureFlagService(),
		di.ConfigResolver(),
	)
	setup.c.Workspace().AddFolder(folder)

	// Setup stored config with initial org, migrated, and user-set
	setup.createStoredConfig("initial-org", true, true)
	setup.c.SetOrganization("global-org-id")

	// Expect RefreshConfigFromLdxSync to be called once with the specific folder
	mockLdxSyncService.EXPECT().
		RefreshConfigFromLdxSync(gomock.Any(), setup.c, gomock.Eq([]types.Folder{folder}), gomock.Any()).
		Times(1)

	// Populate FolderToOrgMapping so AutoDeterminedOrg can be looked up
	cache := setup.c.GetLdxSyncOrgConfigCache()
	cache.SetFolderOrg(setup.folderPath, "auto-determined-org")

	// Call updateFolderConfig with a different org
	newUserOrg := "new-user-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &newUserOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: Org change should be detected and OrgSetByUser should be set to true
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "new-user-org", updatedConfig.PreferredOrg, "PreferredOrg should be updated")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true after org change")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
	// Mock expectations are verified on ctrl.Finish()
}

// migration with user preferences or user changed settings while unmigrated and unauthenticated
func Test_updateFolderConfig_NotMigrated_UserSetOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config without migration flag but with user-set org
	setup.createStoredConfig("user-chosen-org", false, true)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig
	userChosenOrg := "user-chosen-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &userChosenOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: Should migrate and preserve user-set org
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg, "User-set org should be preserved")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should remain true")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should be migrated after update")
}

// Test: AutoDeterminedOrg is missing and needs to be set
// When org settings change, updateFolderConfigOrg is called which sets AutoDeterminedOrg
func Test_updateFolderConfig_MissingAutoDeterminedOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config WITHOUT AutoDeterminedOrg (simulating old config)
	engineConfig := setup.c.Engine().GetConfiguration()
	storedConfig := &types.FolderConfig{
		FolderPath:                  setup.folderPath,
		PreferredOrg:                "test-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
		AutoDeterminedOrg:           "", // Missing in stored config
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, setup.logger)
	require.NoError(setup.t, err)

	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig with DIFFERENT org to trigger updateFolderConfigOrg
	differentTestOrg := "different-test-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &differentTestOrg, // Different to trigger update
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: AutoDeterminedOrg remains empty when LDX-Sync cache is empty
	// AutoDeterminedOrg should only contain what LDX-Sync determined, not a fallback
	// Fallback to global org happens at the point of use (in FolderOrganization)
	updatedConfig := setup.getUpdatedConfig()
	assert.Empty(t, updatedConfig.AutoDeterminedOrg, "AutoDeterminedOrg should remain empty when LDX-Sync cache is empty")
}

// Test: Migrated config where user changes org from auto to manual
func Test_updateFolderConfig_MigratedConfig_SwitchFromAutoToManual(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config in auto mode (migrated, not user-set, empty org)
	setup.createStoredConfig("", true, false)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig with user now setting an org
	userManualOrg := "user-manual-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: &userManualOrg,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: Org change should be detected and OrgSetByUser should be set to true
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-manual-org", updatedConfig.PreferredOrg, "PreferredOrg should be set")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true after user sets org")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
}

func Test_updateFolderConfig_Unauthenticated_UnmigratedUserSetsPreferredOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	engineConfig := c.Engine().GetConfiguration()
	folderPath := types.FilePath(t.TempDir())

	// Setup: Pre-feature folder with zero-value fields (never read during EA)
	storedConfig := &types.FolderConfig{
		FolderPath: folderPath,
	}
	err := storedconfig.UpdateFolderConfig(engineConfig, storedConfig, c.Logger())
	require.NoError(t, err)

	c.SetOrganization("") // Empty org, no auth

	// Action: User sets a preferred org while unauthenticated
	userChosenOrg := "user-chosen-org"
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: &userChosenOrg,
			},
		},
	}
	updateFolderConfig(c, settings, c.Logger(), analytics.TriggerSourceTest)

	// Verify: Should be marked as migrated with OrgSetByUser=true
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, c.Logger())
	require.NoError(t, err)
	assert.Equal(t, "user-chosen-org", updatedConfig.PreferredOrg, "PreferredOrg should be set")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true (LS fixes IDE's false)")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should be marked as migrated")
}

func Test_updateFolderConfig_ProcessesLspFolderConfigUpdates(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config
	setup.createStoredConfig("test-org", true, true)

	// Call updateFolderConfig with LspFolderConfig updates (PATCH semantics)
	// Present=true with Value indicates setting the value
	settings := types.Settings{
		FolderConfigs: []types.LspFolderConfig{
			{
				FolderPath:    setup.folderPath,
				ScanAutomatic: types.NullableField[bool]{true: false},
				ScanNetNew:    types.NullableField[bool]{true: true},
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, analytics.TriggerSourceTest)

	// Verify: UserOverrides should be set in stored config
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic))
	assert.True(t, updatedConfig.HasUserOverride(types.SettingScanNetNew))
}

func Test_validateLockedFields_UsesNewOrgPolicyOnOrgSwitch(t *testing.T) {
	t.Run("rejects locked settings from new org when PreferredOrg changes simultaneously", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		// Folder currently belongs to org-A (no locks)
		setup.createStoredConfig("org-a", true, true)

		// Set up LDX-Sync cache: org-B locks SnykCodeEnabled
		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfigB := types.NewLDXSyncOrgConfig("org-b")
		orgConfigB.SetField(types.SettingSnykCodeEnabled, true, true, false, "group") // locked
		cache.SetOrgConfig(orgConfigB)

		// Set up a real ConfigResolver so validateLockedFields can use it
		resolver := types.NewConfigResolver(cache, nil, setup.c, setup.logger)
		di.SetConfigResolver(resolver)

		// Incoming update: switch to org-B AND change SnykCodeEnabled (which org-B locks)
		newOrg := "org-b"
		incoming := types.LspFolderConfig{
			FolderPath:      setup.folderPath,
			PreferredOrg:    &newOrg,
			SnykCodeEnabled: types.NullableField[bool]{true: false},
			ScanAutomatic:   types.NullableField[bool]{true: true}, // not locked
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(setup.c, folderConfig, &incoming, setup.logger)

		assert.True(t, rejected, "should reject changes to settings locked by the new org")
		// SnykCodeEnabled should have been cleared (locked by org-B)
		assert.True(t, incoming.SnykCodeEnabled.IsOmitted(), "locked setting should be cleared from incoming")
		// ScanAutomatic should still be present (not locked)
		assert.False(t, incoming.ScanAutomatic.IsOmitted(), "non-locked setting should remain in incoming")
	})

	t.Run("allows settings when old org has locks but new org does not", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		// Folder currently belongs to org-A which locks SnykCodeEnabled
		setup.createStoredConfig("org-a", true, true)

		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfigA := types.NewLDXSyncOrgConfig("org-a")
		orgConfigA.SetField(types.SettingSnykCodeEnabled, true, true, false, "group") // locked
		cache.SetOrgConfig(orgConfigA)
		// org-B has no locks

		resolver := types.NewConfigResolver(cache, nil, setup.c, setup.logger)
		di.SetConfigResolver(resolver)

		// Incoming update: switch to org-B AND change SnykCodeEnabled
		newOrg := "org-b"
		incoming := types.LspFolderConfig{
			FolderPath:      setup.folderPath,
			PreferredOrg:    &newOrg,
			SnykCodeEnabled: types.NullableField[bool]{true: false},
		}

		folderConfig := setup.getUpdatedConfig()

		rejected := validateLockedFields(setup.c, folderConfig, &incoming, setup.logger)

		assert.False(t, rejected, "should allow changes when new org has no locks")
		assert.False(t, incoming.SnykCodeEnabled.IsOmitted(), "setting should remain since new org doesn't lock it")
	})
}

func Test_batchClearOrgScopedOverridesOnGlobalChange(t *testing.T) {
	t.Run("clears existing overrides for changed settings", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true, true)

		// Pre-set some folder-level overrides
		storedCfg := setup.getUpdatedConfig()
		storedCfg.SetUserOverride(types.SettingScanAutomatic, false)
		storedCfg.SetUserOverride(types.SettingSnykCodeEnabled, false)
		storedCfg.SetUserOverride(types.SettingSnykOssEnabled, true)
		err := setup.c.UpdateFolderConfig(storedCfg)
		require.NoError(t, err)

		// Global change for ScanAutomatic and SnykCodeEnabled
		pending := map[string]any{
			types.SettingScanAutomatic:   true,
			types.SettingSnykCodeEnabled: true,
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		// Changed settings should have their overrides cleared
		assert.False(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic), "override should be cleared")
		assert.False(t, updatedConfig.HasUserOverride(types.SettingSnykCodeEnabled), "override should be cleared")
		// Unchanged setting should still have its override
		assert.True(t, updatedConfig.HasUserOverride(types.SettingSnykOssEnabled), "unrelated override should be preserved")
	})

	t.Run("skips locked settings per folder", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true, true)

		// Pre-set overrides
		storedCfg := setup.getUpdatedConfig()
		storedCfg.SetUserOverride(types.SettingSnykCodeEnabled, false)
		storedCfg.SetUserOverride(types.SettingScanAutomatic, false)
		err := setup.c.UpdateFolderConfig(storedCfg)
		require.NoError(t, err)

		// Set up LDX-Sync cache with a locked field
		cache := setup.c.GetLdxSyncOrgConfigCache()
		orgConfig := types.NewLDXSyncOrgConfig("test-org")
		orgConfig.SetField(types.SettingSnykCodeEnabled, true, true, false, "group") // locked
		cache.SetOrgConfig(orgConfig)
		cache.SetFolderOrg(setup.folderPath, "test-org")

		pending := map[string]any{
			types.SettingSnykCodeEnabled: true, // locked — override should NOT be cleared
			types.SettingScanAutomatic:   true, // not locked — override should be cleared
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		// Locked setting override should be preserved
		assert.True(t, updatedConfig.HasUserOverride(types.SettingSnykCodeEnabled), "locked setting override should be preserved")
		// Non-locked setting override should be cleared
		assert.False(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic), "non-locked override should be cleared")
	})

	t.Run("filters out non-org-scoped settings", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true, true)

		// Pre-set an override for an org-scoped setting
		storedCfg := setup.getUpdatedConfig()
		storedCfg.SetUserOverride(types.SettingScanAutomatic, false)
		err := setup.c.UpdateFolderConfig(storedCfg)
		require.NoError(t, err)

		pending := map[string]any{
			types.SettingApiEndpoint:   "https://api.snyk.io", // machine-scoped, should be ignored
			types.SettingScanAutomatic: true,                  // org-scoped, override should be cleared
		}

		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		assert.False(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic), "org-scoped override should be cleared")
	})

	t.Run("does nothing for empty pending map", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true, true)

		// Pre-set an override
		storedCfg := setup.getUpdatedConfig()
		storedCfg.SetUserOverride(types.SettingScanAutomatic, false)
		err := setup.c.UpdateFolderConfig(storedCfg)
		require.NoError(t, err)

		// Should not panic or error, and should not clear anything
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, map[string]any{})
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, nil)

		updatedConfig := setup.getUpdatedConfig()
		assert.True(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic), "override should be preserved when pending is empty")
	})

	t.Run("does nothing when no overrides exist", func(t *testing.T) {
		setup := setupFolderConfigTest(t)
		setup.createStoredConfig("test-org", true, true)

		pending := map[string]any{
			types.SettingScanAutomatic: true,
		}

		// Should not panic or error when no overrides exist
		batchClearOrgScopedOverridesOnGlobalChange(setup.c, pending)

		updatedConfig := setup.getUpdatedConfig()
		assert.False(t, updatedConfig.HasUserOverride(types.SettingScanAutomatic))
	})
}

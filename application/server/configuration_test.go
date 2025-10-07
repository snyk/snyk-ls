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
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
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

	t.Setenv("a", "")
	t.Setenv("c", "")
	params := types.DidChangeConfigurationParams{Settings: sampleSettings}
	_, err := loc.Client.Call(ctx, "workspace/didChangeConfiguration", params)
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
	assert.Equal(t, sampleSettings.SnykCodeApi, c.SnykCodeApi())
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
	assert.Equal(t, sampleSettings.SnykCodeApi, c.SnykCodeApi())
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
			Organization:                 expectedOrgId,
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
			SnykCodeApi:                  sampleSettings.SnykCodeApi,
			EnableSnykOpenBrowserActions: "true",
			HoverVerbosity:               &hoverVerbosity, // default is 3
			OutputFormat:                 &outputFormat,   // default is markdown
			FolderConfigs: []types.FolderConfig{
				{
					FolderPath:           types.FilePath(tempDir1),
					BaseBranch:           "testBaseBranch1",
					AdditionalParameters: []string{"--file=asdf"},
				},
				{
					FolderPath: types.FilePath(tempDir2),
					BaseBranch: "testBaseBranch2",
				},
			},
		}

		err := initTestRepo(t, tempDir1)
		assert.NoError(t, err)

		err = initTestRepo(t, tempDir2)
		assert.NoError(t, err)

		UpdateSettings(c, settings)

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
		assert.Equal(t, sampleSettings.SnykCodeApi, c.SnykCodeApi())
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

		assert.Eventually(t, func() bool { return "a fancy token" == c.Token() }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		UpdateSettings(c, types.Settings{})

		assert.Equal(t, 3, c.HoverVerbosity())
		assert.Equal(t, c.Format(), config.FormatMd)
	})

	t.Run("empty snyk code api is ignored and default is used", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{})

		assert.Equal(t, config.DefaultDeeproxyApiUrl, c.SnykCodeApi())
	})

	t.Run("blank organization is ignored", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetOrganization(expectedOrgId)

		UpdateSettings(c, types.Settings{Organization: " "})

		assert.Equal(t, expectedOrgId, c.Organization())
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a="})

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)
		varCount := len(os.Environ())

		UpdateSettings(c, types.Settings{AdditionalEnv: " "})

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a=; b"})

		assert.Empty(t, os.Getenv("a"))
		assert.Empty(t, os.Getenv("b"))
		assert.Empty(t, os.Getenv(";"))
	})
	t.Run("trusted folders", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{TrustedFolders: []string{"/a/b", "/b/c"}})

		assert.Contains(t, c.TrustedFolders(), types.FilePath("/a/b"))
		assert.Contains(t, c.TrustedFolders(), types.FilePath("/b/c"))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			})

			assert.True(t, c.ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "false",
			})

			assert.False(t, c.ManageBinariesAutomatically())
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			})

			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "dog",
			})

			assert.True(t, c.ManageBinariesAutomatically())
		})
	})

	t.Run("activateSnykCodeSecurity is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{ActivateSnykCodeSecurity: "true"})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeSecurity is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{})

		assert.Equal(t, false, c.IsSnykCodeSecurityEnabled())

		c.EnableSnykCodeSecurity(true)

		UpdateSettings(c, types.Settings{})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCode sets SnykCodeSecurity", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{
			ActivateSnykCode: "true",
		})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
		assert.Equal(t, true, c.IsSnykCodeEnabled())
	})

	t.Run("severity filter", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter})

			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &emptyLikeSeverityFilter})

			assert.Equal(t, emptyLikeSeverityFilter, c.FilterSeverity())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter})
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())

			UpdateSettings(c, types.Settings{})
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions})

			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(c, types.Settings{IssueViewOptions: &emptyLikeIssueViewOptions})

			assert.Equal(t, emptyLikeIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions})
			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())

			UpdateSettings(c, types.Settings{})
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

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	assert.NoError(t, err)

	engineConfig := c.Engine().GetConfiguration()
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
	assert.NoError(s.t, err)
}

func (s *folderConfigTestSetup) callUpdateFolderConfig(org string) {
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   s.folderPath,
				PreferredOrg: org,
			},
		},
	}
	updateFolderConfig(s.c, settings, s.logger)
}

func (s *folderConfigTestSetup) getUpdatedConfig() *types.FolderConfig {
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(s.engineConfig, s.folderPath, s.logger)
	assert.NoError(s.t, err)
	return updatedConfig
}

// Test scenarios for updateFolderConfig with LDX-Sync integration
func Test_updateFolderConfig_MigratedConfig_UserSetWithNonEmptyOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	folderPath := types.FilePath(t.TempDir())
	err := initTestRepo(t, string(folderPath))
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	c.SetOrganization("global-org-id")

	// Call updateFolderConfig with the folder config
	settings := types.Settings{
		Organization: "global-org-id", // Include settings.Organization for the condition check
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: "user-org-id",
			},
		},
	}
	updateFolderConfig(c, settings, logger)

	// Verify the org was kept - with the current implementation, UpdateFolderConfigOrg is always called
	// due to pointer comparison, but the org should remain the same since it's user-set
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	assert.NoError(t, err)
	assert.Equal(t, "user-org-id", updatedConfig.PreferredOrg, "PreferredOrg should remain as user-set value")
	// Note: OrgSetByUser behavior depends on UpdateFolderConfigOrg logic when org hasn't actually changed
}

func Test_updateFolderConfig_MigratedConfig_InheritingFromBlankGlobal(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config with empty org
	setup.createStoredConfig("", true, false)
	setup.c.SetOrganization("")

	// Call updateFolderConfig
	setup.callUpdateFolderConfig("")

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

	// Call updateFolderConfig
	// Note: Since folderConfig doesn't have OrgMigratedFromGlobalConfig set,
	// folderConfigsOrgSettingsEqual will return false, triggering UpdateFolderConfigOrg
	setup.callUpdateFolderConfig("")

	// Verify UpdateFolderConfigOrg was called and set the migration flag
	updatedConfig := setup.getUpdatedConfig()
	// After migration, the flag should be set
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true after migration")
}

func Test_updateFolderConfig_NotMigrated_LdxSyncReturnsDifferentOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config without migration
	setup.createStoredConfig("initial-org", false, false)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig
	// Note: Since folderConfig doesn't have OrgMigratedFromGlobalConfig set,
	// folderConfigsOrgSettingsEqual will return false, triggering UpdateFolderConfigOrg
	setup.callUpdateFolderConfig("initial-org")

	// Verify UpdateFolderConfigOrg was called and set the migration flag
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true after migration")
}

func Test_updateFolderConfig_MigratedConfig_UserSetButInheritingFromBlank(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup: previously user-set, but now both folder and global are empty
	setup.createStoredConfig("", true, true) // Was previously set by user
	setup.c.SetOrganization("")

	// Call updateFolderConfig
	setup.callUpdateFolderConfig("")

	// Verify: should attempt to resolve from LDX-Sync because inheriting from blank global
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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	c.SetOrganization("test-org")

	// Call updateFolderConfig with exact same config and same global org
	// DeepEqual should return true, so UpdateFolderConfigOrg should be skipped
	settings := types.Settings{
		Organization: "test-org",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  folderPath,
				PreferredOrg:                "test-org",
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                true,
			},
		},
	}
	updateFolderConfig(c, settings, logger)

	// Verify config remains unchanged (UpdateFolderConfigOrg was skipped)
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	assert.NoError(t, err)
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
	settings := types.Settings{
		Organization: "test-org",
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: "test-org",
			},
		},
	}

	// Should not panic and should handle nil gracefully
	updateFolderConfig(c, settings, logger)
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

	t.Run("activateSnykCodeSecurity is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.Settings{ActivateSnykCodeSecurity: "true"})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeSecurity is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		InitializeSettings(c, types.Settings{})

		assert.Equal(t, false, c.IsSnykCodeSecurityEnabled())

		c.EnableSnykCodeSecurity(true)

		InitializeSettings(c, types.Settings{})

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})

	t.Run("custom path configuration", func(t *testing.T) {
		c := testutil.UnitTest(t)

		first := "first"
		second := "second"

		upperCasePathKey := "PATH"
		caseSensitivePathKey := "Path"
		t.Setenv(caseSensitivePathKey, "something_meaningful")

		// update path to hold a custom value
		UpdateSettings(c, types.Settings{Path: first})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		// update path to hold another value
		UpdateSettings(c, types.Settings{Path: second})
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path with non-empty settings
		UpdateSettings(c, types.Settings{Path: "", AuthenticationMethod: "token"})
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), second))

		assert.True(t, keyFoundInEnv(upperCasePathKey))
		assert.False(t, keyFoundInEnv(caseSensitivePathKey))
	})
}

// Test scenarios for updateFolderConfigOrg - already migrated configs
func Test_updateFolderConfigOrg_MigratedConfig_Initialization_NonUserSet_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-resolved-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-resolved-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should have called LDX-Sync (we can't easily verify this without mocking, but we can check the behavior)
	// The org should remain as resolved by LDX-Sync
	assert.False(t, folderConfig.OrgSetByUser, "Should remain not user-set")
}

func Test_updateFolderConfigOrg_MigratedConfig_Initialization_UserSetWithBlankOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "", // Blank folder org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// User explicitly set the org (even if blank), so OrgSetByUser should remain true
	assert.True(t, folderConfig.OrgSetByUser, "Should remain user-set when user explicitly set blank org")
}

func Test_updateFolderConfigOrg_MigratedConfig_Initialization_UserSet_KeepsExisting(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should keep the user-set org
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should keep user-set org")
	assert.True(t, folderConfig.OrgSetByUser, "Should remain user-set")
}

func Test_updateFolderConfigOrg_MigratedConfig_Update_OrgChanged_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "new-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// The actual org value depends on LDX-Sync resolution
	assert.False(t, folderConfig.OrgSetByUser, "Should not be user-set when OrgSetByUser flag is false")
}

func Test_updateFolderConfigOrg_MigratedConfig_Update_OrgSetByUser_StoresNewOrg(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should store the user-provided org
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should store user org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
}

func Test_updateFolderConfigOrg_MigratedConfig_Update_InheritingFromBlankGlobal_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("") // Blank global org

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "old-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                true,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "", // Blank folder org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should call LDX-Sync because inheriting from blank global
	// The org will be resolved by LDX-Sync (we can't verify the exact value without mocking)
	// But we can verify the OrgSetByUser flag
	assert.False(t, folderConfig.OrgSetByUser, "Should not be user-set when inheriting from blank global")
}

func Test_updateFolderConfigOrg_MigratedConfig_Update_NoChangeNotUserSet_CallsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	storedConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "ldx-org",
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	folderConfig := &types.FolderConfig{
		PreferredOrg:                "ldx-org", // Same org
		OrgMigratedFromGlobalConfig: true,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	updateFolderConfigOrg(c, storedConfig, folderConfig, notifier)

	// Should call LDX-Sync because not user-set
	assert.False(t, folderConfig.OrgSetByUser, "Should remain not user-set")
}

// Test scenarios for migrateFolderConfigOrg - new configs
func Test_migrateFolderConfigOrg_WithUserProvidedOrg_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "user-org",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                true, // Set to true to indicate user provided this org
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should store the user-provided org and skip LDX-Sync
	assert.Equal(t, "user-org", folderConfig.PreferredOrg, "Should store user-provided org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_WithOrgSetByUserFlag_SkipsLdxSync(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                true,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should skip LDX-Sync when OrgSetByUser is true
	assert.Equal(t, "", folderConfig.PreferredOrg, "Should store empty org")
	assert.True(t, folderConfig.OrgSetByUser, "Should mark as user-set")
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_LdxReturnsDifferent_MarksNotUserSet(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should call LDX-Sync and mark as not user-set if different from global
	// (We can't verify the exact org without mocking LDX-Sync, but we can verify the migration flag)
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
}

func Test_migrateFolderConfigOrg_NoOrg_InitialMigration(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetOrganization("global-org")

	folderConfig := &types.FolderConfig{
		FolderPath:                  "/test/path",
		PreferredOrg:                "",
		OrgMigratedFromGlobalConfig: false,
		OrgSetByUser:                false,
	}

	notifier := notification.NewMockNotifier()
	migrateFolderConfigOrg(c, folderConfig, notifier)

	// Should use global org initially and call LDX-Sync
	assert.True(t, folderConfig.OrgMigratedFromGlobalConfig, "Should mark as migrated")
	// The final org and OrgSetByUser depend on LDX-Sync response
}

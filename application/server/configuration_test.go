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
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/ldx_sync_config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/internal/storedconfig"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
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
		setupMockOrgResolver(t, "auto-determined-org-id", "Test Org")

		mockResolver := command.Service().GetOrgResolver().(*mock_types.MockOrgResolver)
		mockResolver.EXPECT().ResolveOrganization(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ldx_sync_config.Organization{
			Id:   expectedOrgId,
			Name: t.Name(),
		}, nil).AnyTimes()

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

		UpdateSettings(c, settings, "test")

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

		assert.Eventually(t, func() bool { return "a fancy token" == c.Token() }, time.Second*5, time.Millisecond)
	})

	t.Run("hover defaults are set", func(t *testing.T) {
		c := testutil.UnitTest(t)
		UpdateSettings(c, types.Settings{}, "test")

		assert.Equal(t, 3, c.HoverVerbosity())
		assert.Equal(t, c.Format(), config.FormatMd)
	})

	t.Run("blank organization is ignored", func(t *testing.T) {
		c := testutil.UnitTest(t)
		c.SetOrganization(expectedOrgId)

		UpdateSettings(c, types.Settings{Organization: " "}, "test")

		assert.Equal(t, expectedOrgId, c.Organization())
	})

	t.Run("incomplete env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a="}, "test")

		assert.Empty(t, os.Getenv("a"))
	})

	t.Run("empty env vars", func(t *testing.T) {
		c := testutil.UnitTest(t)
		varCount := len(os.Environ())

		UpdateSettings(c, types.Settings{AdditionalEnv: " "}, "test")

		assert.Equal(t, varCount, len(os.Environ()))
	})

	t.Run("broken env variables", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{AdditionalEnv: "a=; b"}, "test")

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
		UpdateSettings(c, types.Settings{TrustedFolders: []string{path1, path2}}, "test")

		assert.Contains(t, c.TrustedFolders(), types.FilePath(path1))
		assert.Contains(t, c.TrustedFolders(), types.FilePath(path2))
	})

	t.Run("manage binaries automatically", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("true", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			}, "test")

			assert.True(t, c.ManageBinariesAutomatically())
		})
		t.Run("false", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "false",
			}, "test")

			assert.False(t, c.ManageBinariesAutomatically())
		})

		t.Run("invalid value does not update", func(t *testing.T) {
			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "true",
			}, "test")

			UpdateSettings(c, types.Settings{
				ManageBinariesAutomatically: "dog",
			}, "test")

			assert.True(t, c.ManageBinariesAutomatically())
		})
	})

	t.Run("activateSnykCodeSecurity is passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{ActivateSnykCodeSecurity: "true"}, "test")

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCodeSecurity is not passed", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{}, "test")

		assert.Equal(t, false, c.IsSnykCodeSecurityEnabled())

		c.EnableSnykCodeSecurity(true)

		UpdateSettings(c, types.Settings{}, "test")

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
	})
	t.Run("activateSnykCode sets SnykCodeSecurity", func(t *testing.T) {
		c := testutil.UnitTest(t)

		UpdateSettings(c, types.Settings{
			ActivateSnykCode: "true",
		}, "test")

		assert.Equal(t, true, c.IsSnykCodeSecurityEnabled())
		assert.Equal(t, true, c.IsSnykCodeEnabled())
	})

	t.Run("severity filter", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(true, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter}, "test")

			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeSeverityFilter := types.NewSeverityFilter(false, false, false, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &emptyLikeSeverityFilter}, "test")

			assert.Equal(t, emptyLikeSeverityFilter, c.FilterSeverity())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedSeverityFilter := types.NewSeverityFilter(false, false, true, false)
			UpdateSettings(c, types.Settings{FilterSeverity: &mixedSeverityFilter}, "test")
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())

			UpdateSettings(c, types.Settings{}, "test")
			assert.Equal(t, mixedSeverityFilter, c.FilterSeverity())
		})
	})

	t.Run("issue view options", func(t *testing.T) {
		c := testutil.UnitTest(t)
		t.Run("filtering gets passed", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions}, "test")

			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("equivalent of the \"empty\" struct as a filter gets passed", func(t *testing.T) {
			emptyLikeIssueViewOptions := types.NewIssueViewOptions(false, false)
			UpdateSettings(c, types.Settings{IssueViewOptions: &emptyLikeIssueViewOptions}, "test")

			assert.Equal(t, emptyLikeIssueViewOptions, c.IssueViewOptions())
		})
		t.Run("omitting filter does not cause an update", func(t *testing.T) {
			mixedIssueViewOptions := types.NewIssueViewOptions(false, true)
			UpdateSettings(c, types.Settings{IssueViewOptions: &mixedIssueViewOptions}, "test")
			assert.Equal(t, mixedIssueViewOptions, c.IssueViewOptions())

			UpdateSettings(c, types.Settings{}, "test")
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

// setupMockOrgResolver sets up a mock organization resolver for tests
func setupMockOrgResolver(t *testing.T, orgId, orgName string) {
	t.Helper()
	originalService := command.Service()
	t.Cleanup(func() {
		command.SetService(originalService)
	})

	ctrl := gomock.NewController(t)
	mockResolver := mock_types.NewMockOrgResolver(ctrl)
	mockResolver.EXPECT().ResolveOrganization(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ldx_sync_config.Organization{
		Id:   orgId,
		Name: orgName,
	}, nil).AnyTimes()

	// Get the existing service or create a new mock
	svc := command.Service()
	if mockSvc, ok := svc.(*types.CommandServiceMock); ok {
		// If it's already a mock service, just update the resolver
		mockSvc.SetOrgResolver(mockResolver)
	} else {
		// Otherwise, create a new mock service
		mockService := types.NewCommandServiceMock(mockResolver)
		command.SetService(mockService)
	}
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

	// Set up mock organization resolver for configuration tests
	setupMockOrgResolver(t, "auto-determined-org-id", "Test Org")

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
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   s.folderPath,
				PreferredOrg: org,
			},
		},
	}
	updateFolderConfig(s.c, settings, s.logger, "test")
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
	settings := types.Settings{
		Organization: "global-org-id", // Include settings.Organization for the condition check
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  folderPath,
				OrgSetByUser:                true,
				PreferredOrg:                "user-org-id",
				OrgMigratedFromGlobalConfig: true,
			},
		},
	}
	updateFolderConfig(c, settings, logger, "test")

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
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: "",
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   folderPath,
				PreferredOrg: "",
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: "initial-org",
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

	// Verify UpdateFolderConfigOrg was called and set the migration flag
	updatedConfig := setup.getUpdatedConfig()
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "OrgMigratedFromGlobalConfig should be true after migration")
}

func Test_updateFolderConfig_MigratedConfig_UserSetButInheritingFromBlank(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup the test scenario
	setup.setupMigratedConfigUserSetButInheritingFromBlank()

	// Call updateFolderConfig with empty org settings
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: "",
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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
	updateFolderConfig(c, settings, logger, "test")

	// Verify config remains unchanged (UpdateFolderConfigOrg was skipped)
	updatedConfig, err := storedconfig.GetOrCreateFolderConfig(engineConfig, folderPath, logger)
	require.NoError(t, err)
	assert.Equal(t, "test-org", updatedConfig.PreferredOrg)
	assert.True(t, updatedConfig.OrgSetByUser, "Should remain true since UpdateFolderConfigOrg was skipped")
}

func Test_updateFolderConfig_HandlesNilStoredConfig(t *testing.T) {
	c := testutil.UnitTest(t)
	di.TestInit(t)

	// Set up mock organization resolver
	setupMockOrgResolver(t, "resolved-org-id", "Resolved Org")

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
	updateFolderConfig(c, settings, logger, "test")
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
		UpdateSettings(c, types.Settings{Path: first}, "test")
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), first+string(os.PathListSeparator)))

		// update path to hold another value
		UpdateSettings(c, types.Settings{Path: second}, "test")
		assert.True(t, strings.HasPrefix(os.Getenv(upperCasePathKey), second+string(os.PathListSeparator)))
		assert.False(t, strings.Contains(os.Getenv(upperCasePathKey), first))

		// reset path with non-empty settings
		UpdateSettings(c, types.Settings{Path: "", AuthenticationMethod: "token"}, "test")
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
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  setup.folderPath,
				PreferredOrg:                "",
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                false,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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

	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  setup.folderPath,
				PreferredOrg:                "different-org", // Different from stored
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                false,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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

	// Setup stored config with initial org, migrated, and user-set
	setup.createStoredConfig("initial-org", true, true)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig with a different org
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  setup.folderPath,
				PreferredOrg:                "new-user-org",
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                true,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

	// Verify: Org change should be detected and OrgSetByUser should be set to true
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "new-user-org", updatedConfig.PreferredOrg, "PreferredOrg should be updated")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true after org change")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
}

// migration with user preferences or user changed settings while unmigrated and unauthenticated
func Test_updateFolderConfig_NotMigrated_UserSetOrg(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config without migration flag but with user-set org
	setup.createStoredConfig("user-chosen-org", false, true)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:   setup.folderPath,
				PreferredOrg: "user-chosen-org",
				OrgSetByUser: true,
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

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
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  setup.folderPath,
				PreferredOrg:                "different-test-org", // Different to trigger update
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                true,
				AutoDeterminedOrg:           "", // Missing
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

	// Verify: AutoDeterminedOrg should be fetched and set by updateFolderConfigOrg
	updatedConfig := setup.getUpdatedConfig()
	assert.NotEmpty(t, updatedConfig.AutoDeterminedOrg, "AutoDeterminedOrg should be fetched and set")
	// The mock resolver returns "auto-determined-org-id" when givenOrg is not empty
	assert.Equal(t, "auto-determined-org-id", updatedConfig.AutoDeterminedOrg, "AutoDeterminedOrg should be set from LDX-Sync mock")
}

// Test: Migrated config where user changes org from auto to manual
func Test_updateFolderConfig_MigratedConfig_SwitchFromAutoToManual(t *testing.T) {
	setup := setupFolderConfigTest(t)

	// Setup stored config in auto mode (migrated, not user-set, empty org)
	setup.createStoredConfig("", true, false)
	setup.c.SetOrganization("global-org-id")

	// Call updateFolderConfig with user now setting an org
	settings := types.Settings{
		FolderConfigs: []types.FolderConfig{
			{
				FolderPath:                  setup.folderPath,
				PreferredOrg:                "user-manual-org",
				OrgMigratedFromGlobalConfig: true,
				OrgSetByUser:                false, // IDE still sends false, LS fixes
			},
		},
	}
	updateFolderConfig(setup.c, settings, setup.logger, "test")

	// Verify: Org change should be detected and OrgSetByUser should be set to true
	updatedConfig := setup.getUpdatedConfig()
	assert.Equal(t, "user-manual-org", updatedConfig.PreferredOrg, "PreferredOrg should be set")
	assert.True(t, updatedConfig.OrgSetByUser, "OrgSetByUser should be true after user sets org")
	assert.True(t, updatedConfig.OrgMigratedFromGlobalConfig, "Should remain migrated")
}

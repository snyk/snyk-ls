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
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/pkg/code"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/internal/constants"
	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/storage"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/types"

)

// ConfigResolverForTest is an alias for DefaultConfigResolver.
func ConfigResolverForTest(engine workflow.Engine) *types.ConfigResolver {
	return DefaultConfigResolver(engine)
}

func IntegTest(t *testing.T) workflow.Engine {
	t.Helper()
	engine, _ := prepareTestHelper(t, testsupport.IntegTestEnvVar, "")
	return engine
}

func IntegTestWithEngine(t *testing.T) (workflow.Engine, *config.TokenServiceImpl) {
	t.Helper()
	return prepareTestHelper(t, testsupport.IntegTestEnvVar, "")
}

// TODO: remove useConsistentIgnores once we have fully rolled out the feature
func SmokeTest(t *testing.T, tokenSecretName string) workflow.Engine {
	t.Helper()
	engine, _ := prepareTestHelper(t, testsupport.SmokeTestEnvVar, tokenSecretName)
	return engine
}

// SmokeTestWithEngine returns both engine and tokenService for smoke tests that need to call setupServer.
func SmokeTestWithEngine(t *testing.T, tokenSecretName string) (workflow.Engine, *config.TokenServiceImpl) {
	t.Helper()
	return prepareTestHelper(t, testsupport.SmokeTestEnvVar, tokenSecretName)
}

func UnitTest(t *testing.T) workflow.Engine {
	t.Helper()
	engine, _ := UnitTestWithEngine(t)
	return engine
}

func initStandaloneTestPreEngine(t *testing.T, binarySearchPaths []string) workflow.Engine {
	t.Helper()
	preConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	preConf.Set(types.SettingBinarySearchPaths, binarySearchPaths)
	preConf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	preConf.PersistInStorage(folderconfig.ConfigMainKey)
	preEngine := app.CreateAppEngineWithOptions(app.WithConfiguration(preConf))
	if err := config.InitWorkflows(preEngine); err != nil {
		t.Fatalf("failed to initialize workflows on pre-configured engine: %v", err)
	}
	if err := preEngine.Init(); err != nil {
		t.Logf("unable to initialize workflow engine: %v", err)
	}
	return preEngine
}

func UnitTestWithEngine(t *testing.T) (workflow.Engine, *config.TokenServiceImpl) {
	t.Helper()
	engine, ts := config.InitEngine(initStandaloneTestPreEngine(t, []string{}))
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	err := types.WaitForDefaultEnv(t.Context(), conf)
	if err != nil {
		t.Fatal(err)
	}

	config.SetupLogging(engine, ts, nil)
	ts.SetToken(conf, "00000000-0000-0000-0000-000000000001")
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.FakeAuthentication))
	redirectConfigAndDataHome(t, conf, logger)
	CLIDownloadLockFileCleanUp(t, conf)
	config.SetOrganization(conf, "00000000-0000-0000-0000-000000000000")
	conf.Set(configuration.ORGANIZATION_SLUG, "test-default-org-slug")
	conf.Set(code.ConfigurationSastSettings, &sast_contract.SastResponse{SastEnabled: true, LocalCodeEngine: sast_contract.LocalCodeEngine{
		Enabled: false,
	},
	})
	t.Cleanup(func() {
		cleanupFakeCliFile(conf, logger)
		progress.CleanupChannels()
	})

	return engine, ts
}

func UnitTestWithCtx(t *testing.T) (workflow.Engine, context.Context) {
	t.Helper()
	engine, _ := UnitTestWithEngine(t)
	ctx := ctx2.NewContextWithDependencies(t.Context(), map[string]any{
		ctx2.DepEngine: engine,
	})
	ctx = ctx2.NewContextWithLogger(ctx, engine.GetLogger())
	return engine, ctx
}

func cleanupFakeCliFile(conf configuration.Configuration, logger *zerolog.Logger) {
	cliPath := conf.GetString(configresolver.UserGlobalKey(types.SettingCliPath))
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	stat, err := os.Stat(cliPath)
	if err != nil {
		return
	}
	if stat.Size() < 1000 {
		err = os.Remove(cliPath)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to remove fake CLI")
		}
	}
}

func CLIDownloadLockFileCleanUp(t *testing.T, conf configuration.Configuration) {
	t.Helper()
	lockFileName, _ := config.CLIDownloadLockFileName(conf)
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

func prepareTestHelper(t *testing.T, envVar string, tokenSecretName string) (workflow.Engine, *config.TokenServiceImpl) {
	t.Helper()
	if os.Getenv(envVar) == "" {
		t.Logf("%s is not set", envVar)
		t.SkipNow()
	}

	engine, ts := config.InitEngine(initStandaloneTestPreEngine(t, []string{}))
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	err := types.WaitForDefaultEnv(t.Context(), conf)
	if err != nil {
		t.Fatal(err)
	}
	config.SetupLogging(engine, ts, nil)
	token := testsupport.GetEnvironmentToken(tokenSecretName)
	ts.SetToken(conf, token)
	conf.Set(configresolver.UserGlobalKey(types.SettingAuthenticationMethod), string(types.TokenAuthentication))
	conf.Set(configresolver.UserGlobalKey(types.SettingAutomaticAuthentication), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSendErrorReports), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingTrustEnabled), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewOpenIssues), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingIssueViewIgnoredIssues), true)
	redirectConfigAndDataHome(t, conf, logger)

	CLIDownloadLockFileCleanUp(t, conf)
	t.Cleanup(func() {
		cleanupFakeCliFile(conf, logger)
		progress.CleanupChannels()
	})
	return engine, ts
}

func redirectConfigAndDataHome(t *testing.T, conf configuration.Configuration, logger *zerolog.Logger) {
	t.Helper()
	conf.Set(constants.DataHome, t.TempDir())
	storageFile := filepath.Join(TempDirWithRetry(t), "testStorage")
	s, err := storage.NewStorageWithCallbacks(storage.WithStorageFile(storageFile))
	require.NoError(t, err)
	conf.PersistInStorage(folderconfig.ConfigMainKey)
	conf.SetStorage(s)
	config.SetupStorage(conf, s, logger)
}

func OnlyEnableCode(t *testing.T, engine workflow.Engine) {
	t.Helper()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	w := config.GetWorkspace(conf)
	if w == nil {
		return
	}
	resolver := DefaultConfigResolver(engine)
	for _, folder := range w.Folders() {
		folderConfig := config.GetFolderConfigFromEngine(engine, resolver, folder.Path(), logger)
		types.SetSastSettings(conf, folderConfig.FolderPath, &sast_contract.SastResponse{
			SastEnabled: true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: false,
			},
			AutofixEnabled: true,
		})
	}
}

// SetUpEngineMock creates and configures a mock framework engine for testing.
func SetUpEngineMock(t *testing.T, engine workflow.Engine) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()

	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	engineConfig := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	fs := pflag.NewFlagSet("test-engine-mock", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	require.NoError(t, engineConfig.AddFlagSet(fs))

	mockEngine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(engine.GetLogger()).AnyTimes()

	originalConfig := engine.GetConfiguration()
	engineConfig.Set(constants.DataHome, originalConfig.GetString(constants.DataHome))
	engineConfig.SetStorage(originalConfig.GetStorage())

	fs.VisitAll(func(f *pflag.Flag) {
		key := configresolver.UserGlobalKey(f.Name)
		if originalConfig.IsSet(key) {
			engineConfig.Set(key, originalConfig.Get(key))
		}
	})

	if ws := originalConfig.Get(types.SettingWorkspace); ws != nil {
		engineConfig.Set(types.SettingWorkspace, ws)
	}

	return mockEngine, engineConfig
}

// DefaultConfigResolver creates a ConfigResolver wired to the engine's
// configuration so that GAF-backed settings are resolved correctly in tests.
func DefaultConfigResolver(engine workflow.Engine) *types.ConfigResolver {
	gafConf := engine.GetConfiguration()
	logger := engine.GetLogger()
	fs := pflag.NewFlagSet("test-default-resolver", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConf.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configresolver.New(gafConf, fm)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConf, fm)
	return resolver
}

// WorkflowCapture holds the input data and config captured from a workflow invocation
type WorkflowCapture struct {
	Input  []workflow.Data
	Config configuration.Configuration
}

// MockAndCaptureWorkflowInvocation sets up a mock expectation to capture workflow invocations.
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
		Do(func(_ any, potentialWorkflowData any, potentialConfig any) {
			workflowData, ok := potentialWorkflowData.([]workflow.Data)
			if !ok {
				t.Fatalf("Expected []workflow.Data as second argument to InvokeWithInputAndConfig, got %T", potentialWorkflowData)
				return
			}
			engineConfig, ok := potentialConfig.(configuration.Configuration)
			if !ok {
				t.Fatalf("Expected configuration.Configuration as third argument to InvokeWithInputAndConfig, got %T", potentialConfig)
				return
			}
			ch <- WorkflowCapture{Input: workflowData, Config: engineConfig}
		}).Return(nil, nil)

	return ch
}

// EnableSastAndAutoFix enables SAST and AutoFix in the engine configuration.
func EnableSastAndAutoFix(engine workflow.Engine) {
	engine.GetConfiguration().Set(
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

// SetupFoldersWithOrgs sets up two folders with different organizations.
func SetupFoldersWithOrgs(t *testing.T, engine workflow.Engine) (folderPath1, folderPath2 types.FilePath, globalOrg, folderOrg1, folderOrg2 string) {
	t.Helper()

	globalOrg = "5b1ddf00-0000-0000-0000-000000000001"
	folderOrg1 = "5b1ddf00-0000-0000-0000-000000000002"
	folderOrg2 = "5b1ddf00-0000-0000-0000-000000000003"

	conf := engine.GetConfiguration()
	config.SetOrganization(conf, globalOrg)

	folderPath1 = types.FilePath(t.TempDir())
	folderPath2 = types.FilePath(t.TempDir())

	types.SetPreferredOrgAndOrgSetByUser(conf, folderPath1, folderOrg1, true)
	types.SetPreferredOrgAndOrgSetByUser(conf, folderPath2, folderOrg2, true)

	return folderPath1, folderPath2, globalOrg, folderOrg1, folderOrg2
}

// SetupFolderWithOrg sets up a single folder with a specific organization.
func SetupFolderWithOrg(t *testing.T, engine workflow.Engine, orgUUID string) types.FilePath {
	t.Helper()

	folderPath := types.FilePath(t.TempDir())

	conf := engine.GetConfiguration()
	types.SetPreferredOrgAndOrgSetByUser(conf, folderPath, orgUUID, true)

	return folderPath
}

// SetupGlobalOrgOnly sets up only a global org (no folder-specific org).
func SetupGlobalOrgOnly(t *testing.T, engine workflow.Engine) (folderPath types.FilePath, globalOrg string) {
	t.Helper()

	globalOrg = "00000000-0000-0000-0000-000000000004"
	config.SetOrganization(engine.GetConfiguration(), globalOrg)

	folderPath = types.FilePath(t.TempDir())

	return folderPath, globalOrg
}

// sanitizeTempPattern mirrors the pattern sanitisation from the Go testing library.
func sanitizeTempPattern(name string) string {
	const maxLen = 64
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	const allowed = "!#$%&()+,-.=@^_{}~ "
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune(allowed, r) {
			return r
		}
		return -1
	}, name)
}

// TempDirWithRetry creates a temporary directory and registers a cleanup with retry logic.
func TempDirWithRetry(t *testing.T) string {
	t.Helper()
	pattern := sanitizeTempPattern(t.Name())
	dir, err := os.MkdirTemp("", pattern) //nolint:usetesting // intentionally avoiding t.TempDir() whose non-retryable cleanup fails on Windows
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		const maxAttempts = 5
		for i := 0; i < maxAttempts; i++ {
			err := os.RemoveAll(dir)
			if err == nil {
				return
			}
			if i < maxAttempts-1 && runtime.GOOS == "windows" {
				time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			}
		}
		t.Logf("TempDirWithRetry: could not remove %s after %d attempts", dir, maxAttempts)
	})
	return dir
}

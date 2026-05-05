package config

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/internal/folderconfig"
	"github.com/snyk/snyk-ls/internal/types"
)

func initPreEngineForConfigTests(t *testing.T, binarySearchPaths []string) workflow.Engine {
	t.Helper()
	preConf := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	preConf.Set(types.SettingBinarySearchPaths, binarySearchPaths)
	preConf.Set(cli_constants.EXECUTION_MODE_KEY, cli_constants.EXECUTION_MODE_VALUE_STANDALONE)
	preConf.PersistInStorage(folderconfig.ConfigMainKey)
	preEngine := app.CreateAppEngineWithOptions(app.WithConfiguration(preConf))
	require.NoError(t, InitWorkflows(preEngine))
	require.NoError(t, preEngine.Init())
	return preEngine
}

func initEngineForConfigPackageTests(t *testing.T, binarySearchPaths []string) (workflow.Engine, *TokenServiceImpl) {
	t.Helper()
	engine, ts := InitEngine(initPreEngineForConfigTests(t, binarySearchPaths))
	require.NoError(t, types.WaitForDefaultEnv(t.Context(), engine.GetConfiguration()))
	return engine, ts
}

package mcp

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpconfig "github.com/snyk/studio-mcp/pkg/mcp"
	mcpTypes "github.com/snyk/studio-mcp/shared"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/testutil/workspaceutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCallMcpConfigWorkflow_invokesWorkflowForTrustedFolders(t *testing.T) {
	engine := testutil.UnitTest(t)
	mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

	mockConf.Set(configuration.INTEGRATION_ENVIRONMENT, "test-ide")
	cleanA := filepath.Clean("/trusted/a")
	filePathA := types.FilePath(cleanA)
	cleanB := filepath.Clean("/trusted/b")
	filePathB := types.FilePath(cleanB)
	mockConf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), []types.FilePath{filePathA, filePathB})
	mockConf.Set(configresolver.UserGlobalKey(types.SettingAutoConfigureMcpServer), true)
	mockConf.Set(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq), SecureAtInceptionSmartScan)

	cleanWorkspaceOne := filepath.Clean("/workspace/one")
	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, types.FilePath(cleanWorkspaceOne))

	notifier := notification.NewMockNotifier()
	called := make(chan configuration.Configuration, 1)

	mockEngine.EXPECT().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
			called <- cfg
			return nil, nil
		}).Times(1)

	CallMcpConfigWorkflow(mockConf, mockEngine, mockEngine.GetLogger(), notifier, true, true)

	select {
	case cfg := <-called:
		require.NotNil(t, cfg)
		assert.Equal(t, "test-ide", cfg.GetString(mcpTypes.ToolNameParam))
		assert.Equal(t, "test-ide", cfg.GetString(mcpTypes.IdeConfigPathParam))
		assert.Equal(t, fmt.Sprintf("%s;%s", cleanA, cleanB), cfg.GetString(mcpTypes.TrustedFoldersParam))
		assert.Equal(t, mcpTypes.RuleTypeSmart, cfg.GetString(mcpTypes.RuleTypeParam))
		assert.Equal(t, mcpTypes.RulesGlobalScope, cfg.GetString(mcpTypes.RulesScopeParam))
		assert.Equal(t, cleanWorkspaceOne, cfg.GetString(mcpTypes.WorkspacePathParam))
		assert.True(t, cfg.GetBool(mcpTypes.ConfigureMcpParam))
		assert.True(t, cfg.GetBool(mcpTypes.ConfigureRulesParam))
		assert.NotNil(t, cfg.Get(mcpTypes.McpRegisterCallbackParam))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for InvokeWithConfig")
	}
}

func TestCallMcpConfigWorkflow_setsRemoveWhenAutoConfigureDisabled(t *testing.T) {
	engine := testutil.UnitTest(t)
	mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

	mockConf.Set(configuration.INTEGRATION_ENVIRONMENT, "test-ide")
	mockConf.Set(configresolver.UserGlobalKey(types.SettingAutoConfigureMcpServer), false)
	mockConf.Set(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq), SecureAtInceptionManual)

	_, _ = workspaceutil.SetupWorkspace(t, mockEngine, "/workspace/one")

	notifier := notification.NewMockNotifier()
	called := make(chan configuration.Configuration, 1)

	mockEngine.EXPECT().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
			called <- cfg
			return nil, nil
		}).Times(1)

	CallMcpConfigWorkflow(mockConf, mockEngine, mockEngine.GetLogger(), notifier, true, true)

	select {
	case cfg := <-called:
		require.NotNil(t, cfg)
		assert.True(t, cfg.GetBool(mcpTypes.RemoveParam))
		assert.False(t, cfg.GetBool(mcpTypes.ConfigureMcpParam))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for InvokeWithConfig")
	}
}

func TestCallMcpConfigWorkflow_removeParamCombinations(t *testing.T) {
	tests := []struct {
		name           string
		execFrequency  string
		configureMcp   bool
		configureRules bool
		expectRemove   bool
		expectCfgMcp   bool
	}{
		{
			name:           "manual+configureRules=true sets remove and forces configureMcp=false",
			execFrequency:  SecureAtInceptionManual,
			configureMcp:   true,
			configureRules: true,
			expectRemove:   true,
			expectCfgMcp:   false,
		},
		{
			name:           "manual+configureRules=false does not set remove",
			execFrequency:  SecureAtInceptionManual,
			configureMcp:   true,
			configureRules: false,
			expectRemove:   false,
			expectCfgMcp:   true,
		},
		{
			name:           "non-manual+configureRules=true does not set remove",
			execFrequency:  SecureAtInceptionSmartScan,
			configureMcp:   false,
			configureRules: true,
			expectRemove:   false,
			expectCfgMcp:   false,
		},
		{
			name:           "non-manual+configureRules=false does not set remove",
			execFrequency:  SecureAtInceptionOnCodeGeneration,
			configureMcp:   false,
			configureRules: false,
			expectRemove:   false,
			expectCfgMcp:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := testutil.UnitTest(t)
			mockEngine, mockConf := testutil.SetUpEngineMock(t, engine)

			mockConf.Set(configuration.INTEGRATION_ENVIRONMENT, "test-ide")
			mockConf.Set(configresolver.UserGlobalKey(types.SettingTrustedFolders), nil)
			mockConf.Set(configresolver.UserGlobalKey(types.SettingSecureAtInceptionExecutionFreq), tt.execFrequency)
			_, _ = workspaceutil.SetupWorkspace(t, mockEngine, "/workspace/one")

			notifier := notification.NewMockNotifier()
			called := make(chan configuration.Configuration, 1)

			mockEngine.EXPECT().InvokeWithConfig(mcpconfig.WORKFLOWID_MCP_CONFIG, gomock.Any()).
				DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
					called <- cfg
					return nil, nil
				}).Times(1)

			CallMcpConfigWorkflow(mockConf, mockEngine, mockEngine.GetLogger(), notifier, tt.configureMcp, tt.configureRules)

			select {
			case cfg := <-called:
				require.NotNil(t, cfg)
				assert.Equal(t, tt.expectRemove, cfg.GetBool(mcpTypes.RemoveParam))
				assert.Equal(t, tt.expectCfgMcp, cfg.GetBool(mcpTypes.ConfigureMcpParam))
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for InvokeWithConfig")
			}
		})
	}
}

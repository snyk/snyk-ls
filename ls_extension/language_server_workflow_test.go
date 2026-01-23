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

package ls_extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/app"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_ExtensionEntryPoint(t *testing.T) {
	testutil.UnitTest(t)
	expectedLoglevel := "trace"
	expectedLogPath := t.TempDir()

	engine := app.CreateAppEngineWithOptions()

	//register extension under test
	err := Init(engine)
	assert.Nil(t, err)

	err = engine.Init()
	assert.Nil(t, err)

	engineConfig := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	engineConfig.Set(configuration.DEBUG, true)
	engineConfig.Set("logLevelFlag", expectedLoglevel)
	engineConfig.Set("logPathFlag", expectedLogPath)
	engineConfig.Set("v", true)
	data, err := engine.InvokeWithConfig(WORKFLOWID_LS, engineConfig)
	assert.Nil(t, err)
	assert.Empty(t, data)

	// lsWorkflow overrides the Config.
	c := config.CurrentConfig()
	require.NoError(t, c.WaitForDefaultEnv(t.Context()))

	assert.Equal(t, expectedLoglevel, c.LogLevel())
	assert.Equal(t, expectedLogPath, c.LogPath())
	assert.Equal(t, configCacheTTL, c.Engine().GetConfiguration().GetDuration(configuration.CONFIG_CACHE_TTL))
	assert.False(t, c.Engine().GetConfiguration().GetBool(configuration.CONFIG_CACHE_DISABLED))
}

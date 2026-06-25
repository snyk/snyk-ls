/*
 * © 2026 Snyk Limited
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
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestEnableOnlyProducts_disablesOthers(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	// Seed everything enabled.
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), true)
	conf.Set(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled), true)

	enableOnlyProducts(t, engine, product.ProductCode)

	assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)), "Code should be enabled")
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)), "OSS should be disabled")
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)), "IaC should be disabled")
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)), "Secrets should be disabled")
}

func TestEnableOnlyProducts_enablesMultiple(t *testing.T) {
	engine := testutil.UnitTest(t)
	conf := engine.GetConfiguration()

	enableOnlyProducts(t, engine, product.ProductOpenSource, product.ProductCode)

	assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykCodeEnabled)))
	assert.True(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykOssEnabled)))
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykIacEnabled)))
	assert.False(t, conf.GetBool(configresolver.UserGlobalKey(types.SettingSnykSecretsEnabled)))
}

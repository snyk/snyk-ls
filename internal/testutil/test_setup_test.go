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

package testutil_test

import (
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/infrastructure/issuecache"
	"github.com/snyk/snyk-ls/internal/constants"
	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestUnitTestWithEngineClosesBoltIssueCacheBeforeTempDirCleanup(t *testing.T) {
	var dataHome string
	ok := t.Run("opens bolt issue cache", func(t *testing.T) {
		engine, _ := testutil.UnitTestWithEngine(t)
		conf := engine.GetConfiguration()
		conf.Set(configresolver.UserGlobalKey(types.SettingIssueCacheBackend), "bolt")
		dataHome = conf.GetString(constants.DataHome)

		require.NotNil(t, issuecache.NewIssueCacheForProduct(engine, product.ProductCode))
	})
	require.True(t, ok)
	require.NoError(t, os.RemoveAll(dataHome))
}

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

package types_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

// TestGetGlobalOrganization_ResolvesAndPrimesViaExplicitSet verifies the get-then-set
// behavior. A bare GAF GetString resolves via the default-value function but stores the
// result in GAF's separate defaultCache (not viper), so IsSet stays false. GetGlobalOrganization
// stores the resolved value back, which is what makes IsSet true and primes the IsSet-guarded
// ConfigResolver.GlobalOrg() hot-path read. Mirrors the prod CLI path: caching enabled plus a
// default-value function standing in for GAF's defaultFuncOrganization (/rest/self).
func TestGetGlobalOrganization_ResolvesAndPrimesViaExplicitSet(t *testing.T) {
	conf := configuration.NewWithOpts(configuration.WithCachingEnabled(configuration.NoCacheExpiration))
	conf.AddDefaultValue(configuration.ORGANIZATION, configuration.ImmutableDefaultValueFunction("resolved-org-uuid"))

	require.False(t, conf.IsSet(configuration.ORGANIZATION), "precondition: ORGANIZATION not explicitly set")

	// A bare resolving read returns the value but does NOT mark the key explicitly set.
	require.Equal(t, "resolved-org-uuid", conf.GetString(configuration.ORGANIZATION))
	require.False(t, conf.IsSet(configuration.ORGANIZATION),
		"bare GetString resolves via the default func but must not mark the key explicitly set")

	// GetGlobalOrganization stores the resolved org back (get-then-set), priming viper so IsSet is true.
	got := types.GetGlobalOrganization(conf)
	assert.Equal(t, "resolved-org-uuid", got)
	assert.True(t, conf.IsSet(configuration.ORGANIZATION),
		"GetGlobalOrganization stores the resolved org, so IsSet becomes true (primes hot-path GlobalOrg)")
}

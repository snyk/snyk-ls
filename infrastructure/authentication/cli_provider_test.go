/*
 * © 2022-2024 Snyk Limited
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

package authentication

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/constants"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestCliAuthenticationProvider_AuthenticationMethod(t *testing.T) {
	p := &CliAuthenticationProvider{}
	assert.Equal(t, types.TokenAuthentication, p.AuthenticationMethod())
}

func assertCmd(t *testing.T, expectedArgs []string, actualCmd *exec.Cmd) {
	t.Helper()

	actualArgs := actualCmd.Args[1:]

	assert.Equal(t, expectedArgs, actualArgs)
}

func TestAuth_authCmd(t *testing.T) {
	c := testutil.UnitTest(t)
	ctx := t.Context()
	provider := &CliAuthenticationProvider{c: c}

	authCmd, err := provider.authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

func TestConfig_configGetAPICmd(t *testing.T) {
	c := testutil.UnitTest(t)
	ctx := t.Context()
	provider := &CliAuthenticationProvider{c: c}

	configGetAPICmd, err := provider.configGetAPICmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"config", "get", "api"}, configGetAPICmd)
}

func TestSetAuthURLCmd(t *testing.T) {
	t.Run("works for the default endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{c: c}

		var expectedURL = constants.SNYK_UI_URL + "/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works for a custom endpoint", func(t *testing.T) {
		c := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{c: c}

		var expectedURL = "https://myOwnCompanyURL/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(expectedURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("works when URL is in a substring", func(t *testing.T) {
		c := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{c: c}

		var stringWithURL = "If auth does not automatically redirect you, copy this auth link: " + constants.SNYK_UI_URL + "/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"
		var expectedURL = constants.SNYK_UI_URL + "/login?token=<TOKEN>&utm_medium=cli&utm_source=cli&utm_campaign=cli&os=darwin&docker=false"

		actualURL := provider.getAuthURL(stringWithURL)

		assert.Equal(t, expectedURL, actualURL)
	})

	t.Run("errors when there is a problem extracting the auth url", func(t *testing.T) {
		c := testutil.UnitTest(t)
		provider := &CliAuthenticationProvider{c: c}

		var badURL = "https://invlidAuthURL.com"

		actualURL := provider.getAuthURL(badURL)

		assert.Equal(t, actualURL, "")
	})
}

func TestBuildCLICmd(t *testing.T) {
	t.Run("Insecure is respected", func(t *testing.T) {
		c := testutil.UnitTest(t)
		ctx := t.Context()
		provider := &CliAuthenticationProvider{c: c}
		c.SetCliSettings(&config.CliSettings{
			Insecure: true,
			C:        c,
		})

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Equal(t, []string{".", "auth", "--insecure"}, cmd.Args)
	})

	t.Run("Api endpoint is respected", func(t *testing.T) {
		c := testutil.UnitTest(t)
		ctx := t.Context()
		provider := &CliAuthenticationProvider{c: c}
		c.UpdateApiEndpoints(constants.SNYK_API_EU_URL)

		cmd := provider.buildCLICmd(ctx, "auth")

		assert.Contains(t, cmd.Env, "SNYK_API="+constants.SNYK_API_EU_URL)
	})
}

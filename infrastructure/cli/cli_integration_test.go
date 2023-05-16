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

package cli_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/adrg/xdg"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// todo these tests are hard to understand can we simplify?

//goland:noinspection GoErrorStringFormat
func Test_HandleErrors_MissingTokenError(t *testing.T) { // todo: check if still working
	t.Skip("This test cannot be run automatically, as long as auth is calling an external website.")
	// todo check if an endpoint that is an http mock can be used for auth
	testutil.IntegTest(t)
	config.CurrentConfig().SetToken("")
	ctx := context.Background()
	path, err := install.NewInstaller(di.ErrorReporter(), func() *http.Client { return http.DefaultClient }).Find()
	if err != nil {
		t.Fatal(err)
	}
	config.CurrentConfig().CliSettings().SetPath(path)
	cli := di.SnykCli()
	retry := cli.HandleErrors(ctx, "`snyk` requires an authenticated account. Please run `snyk auth` and try again.")

	assert.True(t, retry)
	assert.Eventually(t, func() bool {
		return config.CurrentConfig().NonEmptyToken()
	}, 5*time.Minute, 10*time.Millisecond, "Didn't install CLI after error, timed out after 5 minutes.")
}

func Test_Execute_HandlesErrors(t *testing.T) {
	// exit status 2: MissingApiTokenError: `snyk` requires an authenticated account. Please run `snyk auth` and try again.
	//    at Object.apiTokenExists (C:\snapshot\snyk\dist\cli\webpack:\snyk\src\lib\api-token.ts:22:11)
	t.Skipf("opens authentication browser window, only activate for dev testing")
	testutil.IntegTest(t)
	testutil.NotOnWindows(t, "moving around CLI config, and file moves under Windows are not very resilient")
	config.CurrentConfig().SetToken("")
	path, err := di.Installer().Find()
	if err != nil {
		t.Fatal(err)
	}
	// remove config for cli, to ensure no token
	cliConfig := xdg.Home + "/.config/configstore/snyk.json"
	cliConfigBackup := cliConfig + time.Now().String() + ".bak"
	_ = os.Rename(cliConfig, cliConfigBackup)
	defer func(oldpath, newpath string) {
		_ = os.Rename(oldpath, newpath)
	}(cliConfigBackup, cliConfig)

	config.CurrentConfig().CliSettings().SetPath(path)
	cli := di.SnykCli()

	response, err := cli.Execute(context.Background(), []string{path, "test"}, ".")

	assert.Error(t, err, string(response))
	assert.Equal(t, "exit status 3", err.Error()) // no supported target files found
}

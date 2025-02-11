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

package oss_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

// This is an integration test that downloads and installs the CLI if necessary
// it uses real CLI output for verification of functionality
func Test_Scan(t *testing.T) {
	testutil.SmokeTest(t, false)
	testutil.CreateDummyProgressListener(t)
	c := config.CurrentConfig()
	c.SetFormat(config.FormatHtml)
	ctx := context.Background()
	di.Init()
	c.SetAuthenticationMethod(types.TokenAuthentication)
	authenticationService := di.AuthenticationService()
	authenticationService.ConfigureProviders(c)

	// ensure CLI is downloaded if not already existent
	if !c.CliSettings().Installed() {
		exec := (&install.Discovery{}).ExecutableName(false)
		destination := filepath.Join(t.TempDir(), exec)
		c.CliSettings().SetPath(destination)
		c.SetManageBinariesAutomatically(true)
		_ = di.Initializer().Init()
	}

	instrumentor := performance.NewInstrumentor()
	er := error_reporting.NewTestErrorReporter()
	notifier := notification.NewMockNotifier()
	cliExecutor := cli.NewExecutor(c, er, notifier)
	scanner := oss.NewCLIScanner(c, instrumentor, er, cliExecutor, di.LearnService(), notifier)

	workingDir, _ := os.Getwd()
	path, _ := filepath.Abs(filepath.Join(workingDir, "testdata", "package.json"))

	// temporary until policy engine doesn't output to stdout anymore
	t.Setenv("SNYK_LOG_LEVEL", "info")
	c.ConfigureLogging(nil)
	c.Engine().GetConfiguration().Set(configuration.DEBUG, false)

	issues, _ := scanner.Scan(ctx, path, workingDir, nil)

	assert.NotEqual(t, 0, len(issues))
	assert.True(t, strings.Contains(issues[0].Message, "<p>"))
	if spanRecorder, ok := instrumentor.(performance.SpanRecorder); ok {
		spans := spanRecorder.Spans()
		assert.Equal(t, "cliScanner.Scan", spans[0].GetOperation())
	} else {
		t.Fail()
	}

	myRange := snyk.Range{Start: snyk.Position{Line: 17}, End: snyk.Position{Line: 17}}
	values, err := scanner.(snyk.InlineValueProvider).GetInlineValues(path, myRange)
	assert.NoError(t, err)
	assert.Greaterf(t, len(values), 0, "no inline values after scan")
}

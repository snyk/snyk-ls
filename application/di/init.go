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

package di

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/adrg/xdg"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	errorreporting "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/domain/observability/performance"
	ux2 "github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/amplitude"
	cli2 "github.com/snyk/snyk-ls/infrastructure/cli"
	auth2 "github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	code2 "github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	sentry2 "github.com/snyk/snyk-ls/infrastructure/sentry"
	"github.com/snyk/snyk-ls/infrastructure/services"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	"github.com/snyk/snyk-ls/internal/notification"
)

var snykApiClient snyk_api.SnykApiClient
var snykCodeClient code2.SnykCodeClient
var snykCodeBundleUploader *code2.BundleUploader
var snykCodeScanner *code2.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner *oss.Scanner
var scanInitializer initialize.Initializer
var authenticationService snyk.AuthenticationService
var instrumentor performance2.Instrumentor
var errorReporter errorreporting.ErrorReporter
var installer install.Installer
var analytics ux2.Analytics
var snykCli cli2.Executor
var hoverService hover.Service
var scanner snyk.Scanner
var cliInitializer *cli2.Initializer

var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initDomain()
}

func initDomain() {
	hoverService = hover.NewDefaultService(analytics)
	scanner = snyk.NewDelegatingScanner(
		scanInitializer,
		instrumentor,
		analytics,
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
}

func initInfrastructure() {
	config.CurrentConfig().AddBinaryLocationsToPath(
		[]string{
			filepath.Join(xdg.Home, ".sdkman"),
			"/usr/lib",
			"/usr/java",
			"/opt",
			"/Library",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		})

	errorReporter = sentry2.NewSentryErrorReporter()
	installer = install.NewInstaller(errorReporter)
	instrumentor = sentry2.NewInstrumentor()
	snykApiClient = snyk_api.NewSnykApiClient()
	analytics = amplitude.NewAmplitudeClient(snykApiClient, errorReporter)
	authProvider := auth2.NewCliAuthenticationProvider(errorReporter)
	authenticationService = services.NewAuthenticationService(authProvider, analytics, errorReporter)
	snykCli = cli2.NewExecutor(authenticationService, errorReporter, analytics)
	snykCodeClient = code2.NewHTTPRepository(instrumentor, errorReporter)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	codeScanNotifier := notification.NewScanNotifier(notification.NewNotifier(), "code")
	snykCodeScanner = code2.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics, codeScanNotifier)
	cliInitializer = cli2.NewInitializer(errorReporter, installer)
	authInitializer := auth2.NewInitializer(authenticationService, errorReporter, analytics)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
}

// TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	analytics = ux2.NewTestAnalytics()
	instrumentor = performance2.NewTestInstrumentor()
	errorReporter = errorreporting.NewTestErrorReporter()
	installer = install.NewFakeInstaller()
	authProvider := auth2.NewFakeCliAuthenticationProvider()
	authenticationService = services.NewAuthenticationService(authProvider, analytics, errorReporter)
	cliInitializer = cli2.NewInitializer(errorReporter, installer)
	authInitializer := auth2.NewInitializer(authenticationService, errorReporter, analytics)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
	fakeClient := &code2.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	snykCli = cli2.NewExecutor(authenticationService, errorReporter, analytics)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	fakeApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}
	codeScanNotifier := notification.NewScanNotifier(notification.NewNotifier(), "code")
	snykCodeScanner = code2.New(snykCodeBundleUploader, fakeApiClient, errorReporter, analytics, codeScanNotifier)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	scanner = snyk.NewDelegatingScanner(scanInitializer, instrumentor, analytics, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	hoverService = hover.NewDefaultService(analytics)
	t.Cleanup(func() {
		fakeClient.Clear()
	})
}

/*
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Instrumentor() performance2.Instrumentor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return instrumentor
}

func ErrorReporter() errorreporting.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func SnykCli() cli2.Executor {
	initMutex.Lock()
	defer initMutex.Unlock()
	return snykCli
}

func Authenticator() snyk.AuthenticationService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return authenticationService
}

func HoverService() hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func Scanner() snyk.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanner
}

func Initializer() initialize.Initializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanInitializer
}

func Analytics() ux2.Analytics {
	initMutex.Lock()
	defer initMutex.Unlock()
	return analytics
}

func OpenSourceScanner() *oss.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return openSourceScanner
}

func Installer() install.Installer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return installer
}

func CliInitializer() *cli2.Initializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return cliInitializer
}

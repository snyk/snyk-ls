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
	"runtime"
	"sync"
	"testing"

	"github.com/adrg/xdg"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
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
var scanNotifier snyk.ScanNotifier
var codeActionService *codeaction.CodeActionsService
var fileWatcher *watcher.FileWatcher
var initMutex = &sync.Mutex{}

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	initInfrastructure()
	initDomain()
	initApplication()
}

func initDomain() {
	hoverService = hover.NewDefaultService(analytics)
	scanner = snyk.NewDelegatingScanner(
		scanInitializer,
		instrumentor,
		analytics,
		scanNotifier,
		snykApiClient,
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
}

func initInfrastructure() {
	c := config.CurrentConfig()
	//goland:noinspection GoBoolExpressions
	if runtime.GOOS == "windows" {
		// on windows add the locations in the background, as it can take a while and shouldn't block the server
		go c.AddBinaryLocationsToPath([]string{
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		})
	} else {
		c.AddBinaryLocationsToPath(
			[]string{
				filepath.Join(xdg.Home, ".sdkman"),
				"/usr/lib",
				"/usr/java",
				"/opt",
				"/Library",
			})
	}

	errorReporter = sentry2.NewSentryErrorReporter()
	installer = install.NewInstaller(errorReporter, c.Engine().GetNetworkAccess().GetUnauthorizedHttpClient)
	instrumentor = sentry2.NewInstrumentor()
	snykApiClient = snyk_api.NewSnykApiClient(c.Engine().GetNetworkAccess().GetHttpClient)
	authFunc := func() (string, error) {
		user, err := snykApiClient.GetActiveUser()
		return user.Id, err
	}
	analytics = amplitude.NewAmplitudeClient(authFunc, errorReporter)
	authProvider := auth2.NewCliAuthenticationProvider(errorReporter)
	authenticationService = services.NewAuthenticationService(snykApiClient, authProvider, analytics, errorReporter)
	snykCli = cli2.NewExecutor(authenticationService, errorReporter, analytics)
	snykCodeClient = code2.NewHTTPRepository(instrumentor, errorReporter, c.Engine().GetNetworkAccess().GetHttpClient)
	snykCodeBundleUploader = code2.NewBundler(snykCodeClient, instrumentor)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	scanNotifier, _ = appNotification.NewScanNotifier(notification.NewNotifier())
	snykCodeScanner = code2.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
	cliInitializer = cli2.NewInitializer(errorReporter, installer)
	authInitializer := auth2.NewInitializer(authenticationService, errorReporter, analytics)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
}

func initApplication() {
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier) // don't use getters or it'll deadlock
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(w, fileWatcher)
	command.ResetService()
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
	snykApiClient = &snyk_api.FakeApiClient{CodeEnabled: true}
	authenticationService = services.NewAuthenticationService(snykApiClient, authProvider, analytics, errorReporter)
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
	scanNotifier, _ = appNotification.NewScanNotifier(notification.NewNotifier())
	snykCodeScanner = code2.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics)
	openSourceScanner = oss.New(instrumentor, errorReporter, analytics, snykCli)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	scanner = snyk.NewDelegatingScanner(
		scanInitializer,
		instrumentor,
		analytics,
		scanNotifier,
		snykApiClient,
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
	hoverService = hover.NewDefaultService(analytics)
	command.ResetService()
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier) // don't use getters or it'll deadlock
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(w, fileWatcher)
	t.Cleanup(
		func() {
			fakeClient.Clear()
		},
	)
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

func AuthenticationService() snyk.AuthenticationService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return authenticationService
}

func HoverService() hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func ScanNotifier() snyk.ScanNotifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanNotifier
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

func CodeActionService() *codeaction.CodeActionsService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return codeActionService
}

func FileWatcher() *watcher.FileWatcher {
	initMutex.Lock()
	defer initMutex.Unlock()
	return fileWatcher
}

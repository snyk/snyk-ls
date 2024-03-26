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

package di

import (
	"path/filepath"
	"runtime"
	"sync"

	codeClient "github.com/snyk/code-client-go"
	codeClientBundle "github.com/snyk/code-client-go/bundle"
	codeClientDeepCode "github.com/snyk/code-client-go/deepcode"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"

	"github.com/adrg/xdg"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	er "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/amplitude"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	cliauth "github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/sentry"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	domainNotify "github.com/snyk/snyk-ls/internal/notification"
)

var snykApiClient snyk_api.SnykApiClient
var snykCodeClient code.SnykCodeClient
var snykCodeBundleUploader *code.BundleUploader
var snykCodeScanner *code.Scanner
var infrastructureAsCodeScanner *iac.Scanner
var openSourceScanner snyk.ProductScanner
var scanInitializer initialize.Initializer
var authenticationService snyk.AuthenticationService
var learnService learn.Service
var instrumentor performance.Instrumentor
var errorReporter er.ErrorReporter
var installer install.Installer
var analytics ux.Analytics
var hoverService hover.Service
var scanner snyk.Scanner
var cliInitializer *cli.Initializer
var scanNotifier snyk.ScanNotifier
var codeActionService *codeaction.CodeActionsService
var fileWatcher *watcher.FileWatcher
var initMutex = &sync.Mutex{}
var notifier notification.Notifier
var codeInstrumentor codeClientObservability.Instrumentor
var codeErrorReporter codeClientObservability.ErrorReporter

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
		authenticationService,
		notifier,
		snykCodeScanner,
		infrastructureAsCodeScanner,
		openSourceScanner,
	)
}

func initInfrastructure() {
	c := config.CurrentConfig()
	//goland:noinspection GoBoolExpressions
	if runtime.GOOS == "windows" {
		go c.AddBinaryLocationsToPath([]string{
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		})
	} else {
		go c.AddBinaryLocationsToPath(
			[]string{
				filepath.Join(xdg.Home, ".sdkman"),
				"/usr/lib",
				"/usr/java",
				"/usr/local/bin",
				"/opt/homebrew/bin",
				"/opt",
				"/Library",
			})
	}

	engine := c.Engine()
	// init NetworkAccess
	networkAccess := engine.GetNetworkAccess()

	notifier = domainNotify.NewNotifier()
	errorReporter = sentry.NewSentryErrorReporter(notifier)
	installer = install.NewInstaller(errorReporter, networkAccess.GetUnauthorizedHttpClient)
	learnService = learn.New(c, networkAccess.GetUnauthorizedHttpClient, errorReporter)
	instrumentor = performance.NewInstrumentor()
	snykApiClient = snyk_api.NewSnykApiClient(networkAccess.GetHttpClient)
	analytics = amplitude.NewAmplitudeClient(snyk.AuthenticationCheck, errorReporter)
	authProvider := cliauth.NewCliAuthenticationProvider(errorReporter)
	authenticationService = snyk.NewAuthenticationService(authProvider, analytics, errorReporter, notifier)
	snykCli := cli.NewExecutor(authenticationService, errorReporter, analytics, notifier)

	if c.Engine().GetConfiguration().GetString(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION {
		snykCli = cli.NewExtensionExecutor()
	}

	codeInstrumentor = code.NewCodeInstrumentor()
	codeErrorReporter = code.NewCodeErrorReporter(errorReporter)

	snykCodeClient = code.NewSnykCodeHTTPClient(codeInstrumentor, codeErrorReporter, networkAccess.GetHttpClient)
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, codeInstrumentor)

	httpClient := codeClientHTTP.NewHTTPClient(engine.GetLogger(), config.CurrentConfig(),
		networkAccess.GetHttpClient, codeInstrumentor,
		codeErrorReporter)
	snykCode := codeClientDeepCode.NewSnykCodeClient(engine.GetLogger(), httpClient, codeInstrumentor)
	bundleManager := codeClientBundle.NewBundleManager(engine.GetLogger(), snykCode, codeInstrumentor, codeErrorReporter)
	codeClientScanner := codeClient.NewCodeScanner(
		bundleManager,
		codeInstrumentor,
		codeErrorReporter,
		engine.GetLogger(),
	)

	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
	openSourceScanner = oss.NewCLIScanner(instrumentor, errorReporter, analytics, snykCli, learnService, notifier, c)
	scanNotifier, _ = appNotification.NewScanNotifier(notifier)
	snykCodeScanner = code.New(snykCodeBundleUploader, snykApiClient, codeErrorReporter, analytics, learnService, notifier,
		codeClientScanner)
	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, snykCli)
	authInitializer := cliauth.NewInitializer(authenticationService, errorReporter, analytics, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
}

func initApplication() {
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier, notifier) // don't use getters or it'll deadlock
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(config.CurrentConfig(), w, fileWatcher, notifier, snykCodeClient)
	command.SetService(command.NewService(
		authenticationService,
		notifier,
		learnService,
		w,
		snykCodeClient,
		snykCodeScanner,
	))
}

/*
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Notifier() notification.Notifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return notifier
}

func ErrorReporter() er.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
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

func Analytics() ux.Analytics {
	initMutex.Lock()
	defer initMutex.Unlock()
	return analytics
}

func Installer() install.Installer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return installer
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

func LearnService() learn.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return learnService
}

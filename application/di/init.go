/*
 * © 2024 Snyk Limited
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

// Package di implements the dependency injection functionality
package di

import (
	"sync"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/internal/types"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	scanner2 "github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/cli_constants"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/sentry"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	domainNotify "github.com/snyk/snyk-ls/internal/notification"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	performance2 "github.com/snyk/snyk-ls/internal/observability/performance"
)

var (
	snykApiClient               snyk_api.SnykApiClient
	snykCodeScanner             *code.Scanner
	infrastructureAsCodeScanner *iac.Scanner
	openSourceScanner           types.ProductScanner
	scanInitializer             initialize.Initializer
	authenticationService       authentication.AuthenticationService
	learnService                learn.Service
	instrumentor                performance2.Instrumentor
	errorReporter               er.ErrorReporter
	installer                   install.Installer
	hoverService                hover.Service
	scanner                     scanner2.Scanner
	featureFlagService          featureflag.Service
	cliInitializer              *cli.Initializer
	scanNotifier                scanner2.ScanNotifier
	codeActionService           *codeaction.CodeActionsService
	fileWatcher                 *watcher.FileWatcher
	initMutex                   = &sync.Mutex{}
	notifier                    domainNotify.Notifier
	codeInstrumentor            codeClientObservability.Instrumentor
	codeErrorReporter           codeClientObservability.ErrorReporter
	scanPersister               persistence.ScanSnapshotPersister
	scanStateAggregator         scanstates.Aggregator
	scanStateChangeEmitter      scanstates.ScanStateChangeEmitter
	snykCli                     cli.Executor
	ldxSyncService              command.LdxSyncService
	configResolver              types.ConfigResolverInterface
	sentBaseline                *types.SentConfigBaseline
)

func Init() {
	initMutex.Lock()
	defer initMutex.Unlock()
	c := config.CurrentConfig()
	initInfrastructure(c)
	initDomain(c)
	initApplication(c)
}

func initDomain(c *config.Config) {
	hoverService = hover.NewDefaultService(c)
	scanner = scanner2.NewDelegatingScanner(c, scanInitializer, instrumentor, scanNotifier, snykApiClient, authenticationService, notifier, scanPersister, scanStateAggregator, configResolver, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	ldxSyncService = command.NewLdxSyncService(configResolver, sentBaseline)
}

func initInfrastructure(c *config.Config) {
	engine := c.Engine()
	gafConfiguration := engine.GetConfiguration()
	// init NetworkAccess
	networkAccess := engine.GetNetworkAccess()
	authorizedClient := networkAccess.GetHttpClient
	unauthorizedHttpClient := networkAccess.GetUnauthorizedHttpClient

	notifier = domainNotify.NewNotifier()
	configResolver = types.NewConfigResolver(c.GetLdxSyncOrgConfigCache(), nil, c, c.Logger())
	sentBaseline = types.NewSentConfigBaseline()
	errorReporter = sentry.NewSentryErrorReporter(c, notifier)
	installer = install.NewInstaller(errorReporter, unauthorizedHttpClient)
	learnService = learn.New(gafConfiguration, c.Logger(), unauthorizedHttpClient)
	instrumentor = performance2.NewInstrumentor()
	featureFlagService = featureflag.New(c)
	snykApiClient = snyk_api.NewSnykApiClient(c, authorizedClient)
	scanPersister = persistence.NewGitPersistenceProvider(c.Logger(), gafConfiguration)
	scanStateChangeEmitter = scanstates.NewSummaryEmitter(c, notifier)
	scanStateAggregator = scanstates.NewScanStateAggregator(c, scanStateChangeEmitter, configResolver)
	// we initialize the service without providers, as we want to wait for initialization to send the auth method
	authenticationService = authentication.NewAuthenticationService(c, nil, errorReporter, notifier)
	snykCli = cli.NewExecutor(c, errorReporter, notifier)

	if gafConfiguration.GetString(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION {
		snykCli = cli.NewExtensionExecutor(c)
	}

	codeInstrumentor = code.NewCodeInstrumentor()
	codeErrorReporter = code.NewCodeErrorReporter(errorReporter)

	infrastructureAsCodeScanner = iac.New(c, instrumentor, errorReporter, snykCli, configResolver)
	openSourceScanner = oss.NewCLIScanner(c, instrumentor, errorReporter, snykCli, learnService, notifier, configResolver)
	scanNotifier, _ = appNotification.NewScanNotifier(c, notifier, configResolver)
	snykCodeScanner = code.New(c, instrumentor, snykApiClient, codeErrorReporter, learnService, featureFlagService, notifier, codeInstrumentor, codeErrorReporter, code.CreateCodeScanner, configResolver)

	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, snykCli)
	authInitializer := authentication.NewInitializer(c, authenticationService, errorReporter, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
}

func initApplication(c *config.Config) {
	w := workspace.New(c, instrumentor, scanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, configResolver) // don't use getters or it'll deadlock
	c.SetWorkspace(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(c, w, fileWatcher, notifier, featureFlagService, configResolver)
	command.SetService(command.NewService(authenticationService, featureFlagService, notifier, learnService, w, snykCodeScanner, snykCli, ldxSyncService, configResolver, sentBaseline))
}

/*
TODO Accessors: This should go away, since all dependencies should be satisfied at startup-time, if needed for testing
they can be returned by the test helper for unit/integration tests
*/

func Notifier() domainNotify.Notifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return notifier
}

func ErrorReporter() er.ErrorReporter {
	initMutex.Lock()
	defer initMutex.Unlock()
	return errorReporter
}

func AuthenticationService() authentication.AuthenticationService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return authenticationService
}

func HoverService() hover.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return hoverService
}

func ScanPersister() persistence.ScanSnapshotPersister {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanPersister
}

func ScanStateAggregator() scanstates.Aggregator {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanStateAggregator
}

func ScanNotifier() scanner2.ScanNotifier {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanNotifier
}

func Scanner() scanner2.Scanner {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanner
}

func Initializer() initialize.Initializer {
	initMutex.Lock()
	defer initMutex.Unlock()
	return scanInitializer
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

func FeatureFlagService() featureflag.Service {
	initMutex.Lock()
	defer initMutex.Unlock()
	return featureFlagService
}

func LdxSyncService() command.LdxSyncService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return ldxSyncService
}

func SetLdxSyncService(service command.LdxSyncService) {
	initMutex.Lock()
	defer initMutex.Unlock()
	ldxSyncService = service
}

func ConfigResolver() types.ConfigResolverInterface {
	initMutex.Lock()
	defer initMutex.Unlock()
	return configResolver
}

func SetConfigResolver(resolver types.ConfigResolverInterface) {
	initMutex.Lock()
	defer initMutex.Unlock()
	configResolver = resolver
}

func SentBaseline() *types.SentConfigBaseline {
	initMutex.Lock()
	defer initMutex.Unlock()
	return sentBaseline
}

func SetSentBaseline(baseline *types.SentConfigBaseline) {
	initMutex.Lock()
	defer initMutex.Unlock()
	sentBaseline = baseline
}

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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/secrets"
	"github.com/snyk/snyk-ls/internal/types"

	codeClientObservability "github.com/snyk/code-client-go/observability"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
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
	snykSecretsScanner          *secrets.Scanner
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
	treeEmitterInstance         *treeview.TreeScanStateEmitter
	snykCli                     cli.Executor
	ldxSyncService              command.LdxSyncService
	configResolver              types.ConfigResolverInterface
)

func Init(engine workflow.Engine, tokenService types.TokenService) {
	initMutex.Lock()
	defer initMutex.Unlock()
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	initInfrastructure(tokenService, conf, engine, logger)
	initDomain(tokenService, conf, engine, logger)
	initApplication(conf, engine, logger)
}

func initDomain(tokenService types.TokenService, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger) {
	hoverService = hover.NewDefaultService(logger)
	scanner = scanner2.NewDelegatingScanner(engine, tokenService, scanInitializer, instrumentor, scanNotifier, snykApiClient, authenticationService, notifier, scanPersister, scanStateAggregator, configResolver, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner, snykSecretsScanner)
	ldxSyncService = command.NewLdxSyncService(configResolver)
}

func initInfrastructure(tokenService types.TokenService, conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger) {
	gafConfiguration := conf

	fs := pflag.NewFlagSet("snyk-ls-config", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConfiguration.AddFlagSet(fs)

	// init NetworkAccess
	networkAccess := engine.GetNetworkAccess()
	authorizedClient := networkAccess.GetHttpClient
	unauthorizedHttpClient := networkAccess.GetUnauthorizedHttpClient

	notifier = domainNotify.NewNotifier()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configresolver.New(gafConfiguration)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConfiguration)
	configResolver = resolver
	errorReporter = sentry.NewSentryErrorReporter(conf, logger, engine, notifier)
	installer = install.NewInstaller(engine, errorReporter, unauthorizedHttpClient)
	learnService = learn.New(gafConfiguration, logger, unauthorizedHttpClient)
	instrumentor = performance2.NewInstrumentor()
	featureFlagService = featureflag.New(conf, logger, engine, configResolver)
	snykApiClient = snyk_api.NewSnykApiClient(conf, logger, authorizedClient)
	scanPersister = persistence.NewGitPersistenceProvider(logger, gafConfiguration)
	summaryEmitter := scanstates.NewSummaryEmitter(conf, logger, notifier, engine, configResolver)
	if treeEmitterInstance != nil {
		treeEmitterInstance.Dispose()
	}
	treeEmitter, treeEmitterErr := treeview.NewTreeScanStateEmitter(conf, logger, notifier)
	if treeEmitterErr != nil {
		logger.Warn().Err(treeEmitterErr).Msg("failed to create tree scan state emitter, using summary emitter only")
		treeEmitterInstance = nil
		scanStateChangeEmitter = summaryEmitter
	} else {
		treeEmitterInstance = treeEmitter
		scanStateChangeEmitter = scanstates.NewCompositeEmitter(summaryEmitter, treeEmitter)
	}
	scanStateAggregator = scanstates.NewScanStateAggregator(conf, logger, scanStateChangeEmitter, configResolver, engine)
	authenticationService = authentication.NewAuthenticationService(engine, tokenService, nil, errorReporter, notifier)
	snykCli = cli.NewExecutor(engine, errorReporter, notifier)

	if gafConfiguration.GetString(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION {
		snykCli = cli.NewExtensionExecutor(engine)
	}

	codeInstrumentor = code.NewCodeInstrumentor()
	codeErrorReporter = code.NewCodeErrorReporter(errorReporter)

	infrastructureAsCodeScanner = iac.New(conf, logger, instrumentor, errorReporter, snykCli, configResolver)
	openSourceScanner = oss.NewCLIScanner(engine, instrumentor, errorReporter, snykCli, learnService, notifier, configResolver)
	scanNotifier, _ = appNotification.NewScanNotifier(notifier, configResolver)
	snykCodeScanner = code.New(engine, instrumentor, snykApiClient, codeErrorReporter, learnService, featureFlagService, notifier, codeInstrumentor, codeErrorReporter, code.CreateCodeScanner, configResolver)
	snykSecretsScanner = secrets.New(conf, engine, logger, instrumentor, snykApiClient, featureFlagService, notifier, configResolver)

	cliInitializer = cli.NewInitializer(conf, logger, errorReporter, installer, notifier, snykCli)
	authInitializer := authentication.NewInitializer(conf, logger, authenticationService, errorReporter, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		authInitializer,
		cliInitializer,
	)
}

func initApplication(conf configuration.Configuration, engine workflow.Engine, logger *zerolog.Logger) {
	w := workspace.New(conf, logger, instrumentor, scanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, configResolver, engine) // don't use getters or it'll deadlock
	config.SetWorkspace(conf, w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(engine, w, fileWatcher, notifier, featureFlagService, configResolver)
	command.SetService(command.NewService(engine, logger, authenticationService, featureFlagService, notifier, learnService, w, snykCodeScanner, snykCli, ldxSyncService, configResolver, scanStateAggregator.StateSnapshot))
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

func DisposeTreeEmitter() {
	initMutex.Lock()
	defer initMutex.Unlock()
	if treeEmitterInstance != nil {
		treeEmitterInstance.Dispose()
	}
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

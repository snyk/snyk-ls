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

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/infrastructure/secrets"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/treeview"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/snyk"
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
	scanInitializer       initialize.Initializer               //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	authenticationService authentication.AuthenticationService //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	learnService          learn.Service                        //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	errorReporter         er.ErrorReporter                     //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	installer             install.Installer                    //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	hoverService          hover.Service                        //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	scanner               scanner2.Scanner                     //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	featureFlagService    featureflag.Service                  //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	scanNotifier          scanner2.ScanNotifier                //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	codeActionService     *codeaction.CodeActionsService       //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	fileWatcher           *watcher.FileWatcher                 //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	initMutex             = &sync.Mutex{}                      //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	notifier              domainNotify.Notifier                //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	scanPersister         persistence.ScanSnapshotPersister    //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	scanStateAggregator   scanstates.Aggregator                //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	treeEmitterInstance   *treeview.TreeScanStateEmitter       //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	ldxSyncService        command.LdxSyncService               //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	configResolver        types.ConfigResolverInterface        //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
	commandService        types.CommandService                 //nolint:gochecknoglobals // legacy process-global DI state; targeted for elimination (IDE-2036)
)

type Dependencies struct {
	AuthenticationService authentication.AuthenticationService
	ConfigResolver        types.ConfigResolverInterface
	FeatureFlagService    featureflag.Service
	Notifier              domainNotify.Notifier
	LearnService          learn.Service
	LdxSyncService        command.LdxSyncService
	ScanStateAggregator   scanstates.Aggregator
	InlineValueProvider   snyk.InlineValueProvider
	TreeEmitter           command.TreeEmitter
	// Handler-accessed dependencies (previously read via di.*() globals).
	// Note: Initializer is intentionally absent — it is a process-lifecycle
	// dependency used during startup only.
	Scanner           scanner2.Scanner
	HoverService      hover.Service
	ScanNotifier      scanner2.ScanNotifier
	ScanPersister     persistence.ScanSnapshotPersister
	FileWatcher       *watcher.FileWatcher
	ErrorReporter     er.ErrorReporter
	CodeActionService *codeaction.CodeActionsService
	Installer         install.Installer
	CommandService    types.CommandService
	// ProgressChannel receives scanner progress events that createProgressListener
	// drains and forwards to the LSP client. Currently points to the process-global
	// progress.ToServerProgressChannel because all scanners write to it via
	// progress.NewTracker(). Full per-server isolation requires migrating scanner
	// callers to progress.NewTrackerWithChannel — deferred to a follow-up.
	ProgressChannel chan types.ProgressParams
}

// buildDependencies constructs a fully-initialized set of production dependencies
// using only local variables, so multiple callers (e.g. parallel smoke-test servers)
// are safe to run concurrently without data races on package-level globals.
// It returns the Dependencies struct, the initialize.Initializer, and the concrete
// *treeview.TreeScanStateEmitter (nil when creation failed) so Init() can assign
// the global treeEmitterInstance without a runtime type assertion.
func buildDependencies(engine workflow.Engine, tokenService types.TokenService, progressCh chan types.ProgressParams) (Dependencies, initialize.Initializer, *treeview.TreeScanStateEmitter) {
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()

	gafConfiguration := conf
	gafConfiguration.Set(configuration.STOP_REQUESTS_WITHOUT_AUTH, true)

	fs := pflag.NewFlagSet("snyk-ls-config", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConfiguration.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	// Network access
	networkAccess := engine.GetNetworkAccess()
	authorizedClient := networkAccess.GetHttpClient
	unauthorizedHttpClient := networkAccess.GetUnauthorizedHttpClient

	// Infrastructure layer — all local variables
	localNotifier := domainNotify.NewNotifier()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configresolver.New(gafConfiguration, fm)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConfiguration, fm)
	localConfigResolver := types.ConfigResolverInterface(resolver)

	localErrorReporter := sentry.NewSentryErrorReporter(conf, logger, engine, localNotifier, localConfigResolver)
	localInstaller := install.NewInstaller(engine, localErrorReporter, unauthorizedHttpClient, localConfigResolver)
	localLearnService := learn.New(gafConfiguration, logger, unauthorizedHttpClient)
	localInstrumentor := performance2.NewInstrumentor()
	localFeatureFlagService := featureflag.New(conf, logger, engine, localConfigResolver)
	localSnykApiClient := snyk_api.NewSnykApiClient(conf, logger, authorizedClient, localConfigResolver)
	localScanPersister := persistence.NewGitPersistenceProvider(logger, gafConfiguration)

	localSummaryEmitter := scanstates.NewSummaryEmitter(conf, logger, localNotifier, engine, localConfigResolver)
	localTreeEmitter, localTreeEmitterErr := treeview.NewTreeScanStateEmitter(conf, logger, localNotifier)
	var localTreeEmitterInstance *treeview.TreeScanStateEmitter
	var localScanStateChangeEmitter scanstates.ScanStateChangeEmitter
	if localTreeEmitterErr != nil {
		logger.Warn().Err(localTreeEmitterErr).Msg("failed to create tree scan state emitter, using summary emitter only")
		localTreeEmitterInstance = nil
		localScanStateChangeEmitter = localSummaryEmitter
	} else {
		localTreeEmitterInstance = localTreeEmitter
		localScanStateChangeEmitter = scanstates.NewCompositeEmitter(localSummaryEmitter, localTreeEmitter)
	}

	localScanStateAggregator := scanstates.NewScanStateAggregator(conf, logger, localScanStateChangeEmitter, localConfigResolver, engine)
	localAuthenticationService := authentication.NewAuthenticationService(engine, tokenService, nil, localErrorReporter, localNotifier, localConfigResolver)

	localSnykCli := cli.NewExecutor(engine, localErrorReporter, localNotifier, localConfigResolver)
	if gafConfiguration.GetString(cli_constants.EXECUTION_MODE_KEY) == cli_constants.EXECUTION_MODE_VALUE_EXTENSION {
		localSnykCli = cli.NewExtensionExecutor(engine, localConfigResolver)
	}

	localCodeInstrumentor := code.NewCodeInstrumentor()
	localCodeErrorReporter := code.NewCodeErrorReporter(localErrorReporter)

	localIaCScanner := iac.New(conf, logger, localInstrumentor, localErrorReporter, localSnykCli, localConfigResolver, progressCh)
	localOpenSourceScanner := oss.NewCLIScanner(engine, localInstrumentor, localErrorReporter, localSnykCli, localLearnService, localNotifier, localConfigResolver, progressCh)
	localScanNotifier, _ := appNotification.NewScanNotifier(localNotifier, localConfigResolver)
	localSnykCodeScanner := code.New(engine, localInstrumentor, localSnykApiClient, localCodeErrorReporter, localLearnService, localFeatureFlagService, localNotifier, localCodeInstrumentor, localCodeErrorReporter, code.CreateCodeScanner, localConfigResolver, progressCh)
	localSecretsScanner := secrets.New(conf, engine, logger, localInstrumentor, localSnykApiClient, localFeatureFlagService, localNotifier, localConfigResolver)

	localCLIInitializer := cli.NewInitializer(conf, logger, localErrorReporter, localInstaller, localNotifier, localSnykCli, localConfigResolver)
	localAuthInitializer := authentication.NewInitializer(conf, logger, localAuthenticationService, localErrorReporter, localNotifier, localConfigResolver)
	localScanInitializer := initialize.NewDelegatingInitializer(
		localAuthInitializer,
		localCLIInitializer,
	)

	// Domain layer
	localHoverService := hover.NewDefaultService(logger)
	localScanner := scanner2.NewDelegatingScanner(engine, tokenService, localScanInitializer, localInstrumentor, localScanNotifier, localSnykApiClient, localAuthenticationService, localNotifier, localScanPersister, localScanStateAggregator, localConfigResolver, localSnykCodeScanner, localIaCScanner, localOpenSourceScanner, localSecretsScanner)
	localLdxSyncService := command.NewLdxSyncService(localConfigResolver)

	// Application layer
	w := workspace.New(conf, logger, localInstrumentor, localScanner, localHoverService, localScanNotifier, localNotifier, localScanPersister, localScanStateAggregator, localFeatureFlagService, localConfigResolver, engine)
	config.SetWorkspace(conf, w)
	localFileWatcher := watcher.NewFileWatcher()
	localCodeActionService := codeaction.NewService(engine, w, localFileWatcher, localNotifier, localFeatureFlagService, localConfigResolver)
	localCommandService := command.NewService(engine, logger, localAuthenticationService, localFeatureFlagService, localNotifier, localLearnService, w, localSnykCodeScanner, localSnykCli, localLdxSyncService, localConfigResolver, localScanStateAggregator.StateSnapshot)

	var localInlineValueProvider snyk.InlineValueProvider
	if ivp, ok := localScanner.(snyk.InlineValueProvider); ok {
		localInlineValueProvider = ivp
	}

	deps := Dependencies{
		AuthenticationService: localAuthenticationService,
		ConfigResolver:        localConfigResolver,
		FeatureFlagService:    localFeatureFlagService,
		Notifier:              localNotifier,
		LearnService:          localLearnService,
		LdxSyncService:        localLdxSyncService,
		ScanStateAggregator:   localScanStateAggregator,
		InlineValueProvider:   localInlineValueProvider,
		TreeEmitter:           localTreeEmitterInstance,
		Scanner:               localScanner,
		HoverService:          localHoverService,
		ScanNotifier:          localScanNotifier,
		ScanPersister:         localScanPersister,
		FileWatcher:           localFileWatcher,
		ErrorReporter:         localErrorReporter,
		CodeActionService:     localCodeActionService,
		Installer:             localInstaller,
		CommandService:        localCommandService,
		ProgressChannel:       progressCh,
	}
	return deps, localScanInitializer, localTreeEmitterInstance
}

func Init(engine workflow.Engine, tokenService types.TokenService) Dependencies {
	initMutex.Lock()
	defer initMutex.Unlock()

	if treeEmitterInstance != nil {
		treeEmitterInstance.Dispose()
	}

	deps, initializer, treeEmitter := buildDependencies(engine, tokenService, progress.ToServerProgressChannel)

	// Populate package-level globals for accessor functions.
	notifier = deps.Notifier
	configResolver = deps.ConfigResolver
	errorReporter = deps.ErrorReporter
	authenticationService = deps.AuthenticationService
	hoverService = deps.HoverService
	scanPersister = deps.ScanPersister
	scanStateAggregator = deps.ScanStateAggregator
	scanNotifier = deps.ScanNotifier
	scanner = deps.Scanner
	installer = deps.Installer
	codeActionService = deps.CodeActionService
	fileWatcher = deps.FileWatcher
	learnService = deps.LearnService
	featureFlagService = deps.FeatureFlagService
	ldxSyncService = deps.LdxSyncService
	treeEmitterInstance = treeEmitter
	commandService = deps.CommandService
	scanInitializer = initializer

	return deps
}

// RealDependencies builds a fully-initialized set of production dependencies
// using only local variables. It mirrors Init but never writes to any
// package-level global, so multiple callers (e.g. parallel smoke-test servers)
// are safe to run concurrently without a data race.
func RealDependencies(engine workflow.Engine, tokenService types.TokenService) Dependencies {
	progressCh := make(chan types.ProgressParams, 1000)
	deps, _, _ := buildDependencies(engine, tokenService, progressCh)
	return deps
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

// SetFeatureFlagService replaces the global featureFlagService for future calls
// to FeatureFlagService(). Objects already constructed before this call retain
// their previous reference. Intended for test use only.
func SetFeatureFlagService(service featureflag.Service) {
	initMutex.Lock()
	defer initMutex.Unlock()
	featureFlagService = service
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

func CommandService() types.CommandService {
	initMutex.Lock()
	defer initMutex.Unlock()
	return commandService
}

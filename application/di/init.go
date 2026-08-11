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
	"context"

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
	"github.com/snyk/snyk-ls/domain/snyk/remediation"
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

type Dependencies struct {
	AuthenticationService authentication.AuthenticationService
	ConfigResolver        types.ConfigResolverInterface
	FeatureFlagService    featureflag.Service
	Notifier              domainNotify.Notifier
	LearnService          learn.Service
	LdxSyncService        command.LdxSyncService
	ScanStateAggregator   scanstates.Aggregator
	InlineValueProvider   snyk.InlineValueProvider
	// TreeEmitter is the concrete type rather than command.TreeEmitter because
	// the server owns its disposal on shutdown, and disposal is a lifecycle
	// concern that the consumer-facing interface has no reason to carry. Nil
	// when emitter construction failed; Dispose tolerates that.
	TreeEmitter *treeview.TreeScanStateEmitter
	// Handler-accessed dependencies. Only what handlers read belongs here, which
	// is why initialize.Initializer does not: no handler reads it, it is consumed
	// once during startup by NewDelegatingScanner.
	Scanner             scanner2.Scanner
	HoverService        hover.Service
	ScanNotifier        scanner2.ScanNotifier
	ScanPersister       persistence.ScanSnapshotPersister
	FileWatcher         *watcher.FileWatcher
	ErrorReporter       er.ErrorReporter
	CodeActionService   *codeaction.CodeActionsService
	RemediationNotifier remediation.FileChangeNotifier
	Installer           install.Installer
	CommandService      types.CommandService
	// ProgressTracker is the per-server Tracker of the progress channel and the
	// token→task registry [IDE-2036]. Each server instance has its own Tracker so
	// progress events from one server cannot leak to another server's listener.
	ProgressTracker *progress.Tracker
	// ScanCtx is a server-lifetime context for workspace scan goroutines.
	// Canceling ScanCancel on shutdown ensures in-flight scan goroutines exit
	// cleanly, preventing file-handle leaks on Windows [IDE-2036].
	ScanCtx    context.Context
	ScanCancel context.CancelFunc
}

// Init constructs a fully-initialized set of production dependencies using only
// local variables, so multiple callers (e.g. parallel smoke-test servers) are
// safe to run concurrently. The caller owns the returned graph, including
// disposing Dependencies.TreeEmitter and calling Dependencies.ScanCancel.
func Init(engine workflow.Engine, tokenService types.TokenService) Dependencies {
	conf := engine.GetConfiguration()
	logger := engine.GetLogger()
	progressTracker := progress.NewTracker(logger)

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
	localInstaller := install.NewInstaller(engine, localErrorReporter, unauthorizedHttpClient, localConfigResolver, progressTracker)
	localLearnService := learn.New(gafConfiguration, logger, unauthorizedHttpClient)
	localInstrumentor := performance2.NewInstrumentor()
	localFeatureFlagService := featureflag.New(conf, logger, engine, localConfigResolver)
	localSnykApiClient := snyk_api.NewSnykApiClient(conf, logger, authorizedClient, localConfigResolver)
	localScanPersister := persistence.NewGitPersistenceProvider(logger, gafConfiguration)

	localSummaryEmitter := scanstates.NewSummaryEmitter(conf, logger, localNotifier, engine, localConfigResolver)
	localTreeEmitter, localTreeEmitterErr := treeview.NewTreeScanStateEmitter(conf, logger, localNotifier)
	var localScanStateChangeEmitter scanstates.ScanStateChangeEmitter
	if localTreeEmitterErr != nil {
		logger.Warn().Err(localTreeEmitterErr).Msg("failed to create tree scan state emitter, using summary emitter only")
		localTreeEmitter = nil // Dependencies.TreeEmitter promises nil on failure
		localScanStateChangeEmitter = localSummaryEmitter
	} else {
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

	localIaCScanner := iac.New(conf, logger, localInstrumentor, localErrorReporter, localSnykCli, localConfigResolver, progressTracker)
	localOpenSourceScanner := oss.NewCLIScanner(engine, localInstrumentor, localErrorReporter, localSnykCli, localLearnService, localNotifier, localConfigResolver, progressTracker)
	localScanNotifier, _ := appNotification.NewScanNotifier(localNotifier, localConfigResolver)
	localSnykCodeScanner := code.New(engine, localInstrumentor, localSnykApiClient, localCodeErrorReporter, localLearnService, localFeatureFlagService, localNotifier, localCodeInstrumentor, localCodeErrorReporter, code.CreateCodeScanner, localConfigResolver, progressTracker)
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

	// Server-lifetime scan context: canceled on shutdown so that in-flight scan
	// goroutines exit cleanly, preventing file-handle leaks on Windows [IDE-2036].
	// Created before the command service so it can be injected at construction [Decision D1].
	localScanCtx, localScanCancel := context.WithCancel(context.Background())

	// Application layer
	w := workspace.New(conf, logger, localInstrumentor, localScanner, localHoverService, localScanNotifier, localNotifier, localScanPersister, localScanStateAggregator, localFeatureFlagService, localConfigResolver, engine)
	config.SetWorkspace(conf, w)
	localFileWatcher := watcher.NewFileWatcher()

	localRemediationProvider := remediation.NewRemyProvider(engine, nil)
	localRemediationNotifier, _ := localRemediationProvider.(remediation.FileChangeNotifier)
	localFolderRemediator, _ := localRemediationProvider.(remediation.FolderRemediator)

	localCodeActionService := codeaction.NewService(engine, w, localFileWatcher, localNotifier, localFeatureFlagService, localConfigResolver, localRemediationProvider)
	localCommandService := command.NewService(engine, logger, localAuthenticationService, localFeatureFlagService, localNotifier, localLearnService, w, localSnykCodeScanner, localSnykCli, localLdxSyncService, localConfigResolver, localScanStateAggregator.StateSnapshot, localFolderRemediator, localScanCtx)

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
		TreeEmitter:           localTreeEmitter,
		Scanner:               localScanner,
		HoverService:          localHoverService,
		ScanNotifier:          localScanNotifier,
		ScanPersister:         localScanPersister,
		FileWatcher:           localFileWatcher,
		ErrorReporter:         localErrorReporter,
		CodeActionService:     localCodeActionService,
		RemediationNotifier:   localRemediationNotifier,
		Installer:             localInstaller,
		CommandService:        localCommandService,
		ProgressTracker:       progressTracker,
		ScanCtx:               localScanCtx,
		ScanCancel:            localScanCancel,
	}
	return deps
}

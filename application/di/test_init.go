/*
 * © 2023 Snyk Limited
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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	scanner2 "github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/featureflag"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	domainNotify "github.com/snyk/snyk-ls/internal/notification"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
)

// TestInit builds an isolated set of dependencies for a single test run.
// The returned Dependencies struct is self-contained; all service fields are
// independent per-call instances.
//
// Remaining global side effects (not safe for parallel tests without further work):
//   - types.SetGlobalSystemDefault — stores into the per-engine configuration.
func TestInit(t *testing.T, engine workflow.Engine, tokenService types.TokenService, overrideDeps *Dependencies) Dependencies {
	t.Helper()
	gafConfiguration := engine.GetConfiguration()
	types.SetGlobalSystemDefault(gafConfiguration, types.SettingCliPath, filepath.Join(t.TempDir(), "fake-cli"))

	return buildTestDependencies(t, engine, tokenService, overrideDeps)
}

//nolint:gocyclo // high branching is inherent: one nil-check per overrideable dependency
func buildTestDependencies(t *testing.T, engine workflow.Engine, tokenService types.TokenService, overrideDeps *Dependencies) Dependencies {
	t.Helper()
	gafConfiguration := engine.GetConfiguration()

	var localNotifier domainNotify.Notifier
	if overrideDeps != nil && overrideDeps.Notifier != nil {
		localNotifier = overrideDeps.Notifier
	} else {
		localNotifier = domainNotify.NewNotifier()
	}

	fs := pflag.NewFlagSet("snyk-ls-config-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConfiguration.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	logger := engine.GetLogger()

	var localConfigResolver types.ConfigResolverInterface
	if overrideDeps != nil && overrideDeps.ConfigResolver != nil {
		localConfigResolver = overrideDeps.ConfigResolver
	} else {
		resolver := types.NewConfigResolver(logger)
		prefixKeyResolver := configresolver.New(gafConfiguration, fm)
		resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConfiguration, fm)
		localConfigResolver = resolver
	}

	localInstrumentor := performance.NewInstrumentor()
	localErrorReporter := er.NewTestErrorReporter(engine)
	localInstaller := install.NewFakeInstaller(engine, localConfigResolver)
	authProvider := authentication.NewFakeCliAuthenticationProvider(engine)
	localSnykApiClient := &snyk_api.FakeApiClient{CodeEnabled: true}

	var localAuthenticationService authentication.AuthenticationService
	if overrideDeps != nil && overrideDeps.AuthenticationService != nil {
		localAuthenticationService = overrideDeps.AuthenticationService
	} else {
		localAuthenticationService = authentication.NewAuthenticationService(engine, tokenService, authProvider, localErrorReporter, localNotifier, localConfigResolver)
	}

	localSnykCli := cli.NewExecutor(engine, localErrorReporter, localNotifier, localConfigResolver)
	localCLIInitializer := cli.NewInitializer(gafConfiguration, logger, localErrorReporter, localInstaller, localNotifier, localSnykCli, localConfigResolver)
	localAuthInitializer := authentication.NewInitializer(gafConfiguration, logger, localAuthenticationService, localErrorReporter, localNotifier, localConfigResolver)
	localScanInitializer := initialize.NewDelegatingInitializer(
		localCLIInitializer,
		localAuthInitializer,
	)

	localCodeInstrumentor := code.NewCodeInstrumentor()
	localScanNotifier, _ := appNotification.NewScanNotifier(localNotifier, localConfigResolver)

	var localLearnService learn.Service
	if overrideDeps != nil && overrideDeps.LearnService != nil {
		localLearnService = overrideDeps.LearnService
	} else {
		ctrl := gomock.NewController(t)
		learnMock := mock_learn.NewMockService(ctrl)
		learnMock.EXPECT().GetAllLessons().Return([]learn.Lesson{{}}, nil).AnyTimes()
		learnMock.EXPECT().MaintainCacheFunc().AnyTimes()
		learnMock.
			EXPECT().
			GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(&learn.Lesson{}, nil).AnyTimes()
		localLearnService = learnMock
	}

	localScanPersister := persistence.NopScanPersister{}
	var localScanStateAggregator scanstates.Aggregator
	if overrideDeps != nil && overrideDeps.ScanStateAggregator != nil {
		localScanStateAggregator = overrideDeps.ScanStateAggregator
	} else {
		localScanStateAggregator = scanstates.NewNoopStateAggregator()
	}
	localCodeErrorReporter := code.NewCodeErrorReporter(localErrorReporter)

	var localFeatureFlagService featureflag.Service
	if overrideDeps != nil && overrideDeps.FeatureFlagService != nil {
		localFeatureFlagService = overrideDeps.FeatureFlagService
	} else {
		localFeatureFlagService = featureflag.New(gafConfiguration, logger, engine, localConfigResolver)
	}

	localSnykCodeScanner := code.New(engine, localInstrumentor, localSnykApiClient, localCodeErrorReporter, localLearnService, localFeatureFlagService, localNotifier, localCodeInstrumentor, localCodeErrorReporter, code.NewFakeCodeScannerClient, localConfigResolver)
	localOpenSourceScanner := oss.NewCLIScanner(engine, localInstrumentor, localErrorReporter, localSnykCli, localLearnService, localNotifier, localConfigResolver)
	localIaCScanner := iac.New(gafConfiguration, logger, localInstrumentor, localErrorReporter, localSnykCli, localConfigResolver)
	localScanner := scanner2.NewDelegatingScanner(engine, tokenService, localScanInitializer, localInstrumentor, localScanNotifier, localSnykApiClient, localAuthenticationService, localNotifier, localScanPersister, localScanStateAggregator, localConfigResolver, localSnykCodeScanner, localIaCScanner, localOpenSourceScanner)

	var localHoverService hover.Service
	if overrideDeps != nil && overrideDeps.HoverService != nil {
		localHoverService = overrideDeps.HoverService
	} else {
		localHoverService = hover.NewDefaultService(logger)
	}

	var localLdxSyncService command.LdxSyncService
	if overrideDeps != nil && overrideDeps.LdxSyncService != nil {
		localLdxSyncService = overrideDeps.LdxSyncService
	} else {
		localLdxSyncService = command.NewLdxSyncService(localConfigResolver)
	}

	var localCommandService types.CommandService
	if overrideDeps != nil && overrideDeps.CommandService != nil {
		localCommandService = overrideDeps.CommandService
	} else {
		localCommandService = types.NewCommandServiceMock()
	}

	// Default to the global progress channel so progress.NewTracker() events
	// (which always write to progress.ToServerProgressChannel) reach the server.
	// Tests that need per-server isolation must set overrideDeps.ProgressChannel
	// to a dedicated channel and use progress.NewTrackerWithChannel to route
	// tracker events to that channel explicitly.
	var localProgressChannel chan types.ProgressParams
	if overrideDeps != nil && overrideDeps.ProgressChannel != nil {
		localProgressChannel = overrideDeps.ProgressChannel
	} else {
		localProgressChannel = progress.ToServerProgressChannel
	}

	w := workspace.New(gafConfiguration, logger, localInstrumentor, localScanner, localHoverService, localScanNotifier, localNotifier, localScanPersister, localScanStateAggregator, localFeatureFlagService, localConfigResolver, engine)
	config.SetWorkspace(gafConfiguration, w)
	localFileWatcher := watcher.NewFileWatcher()
	localCodeActionService := codeaction.NewService(engine, w, localFileWatcher, localNotifier, localFeatureFlagService, localConfigResolver)

	var localInlineValueProvider snyk.InlineValueProvider
	if ivp, ok := localScanner.(snyk.InlineValueProvider); ok {
		localInlineValueProvider = ivp
	}

	return Dependencies{
		AuthenticationService: localAuthenticationService,
		ConfigResolver:        localConfigResolver,
		FeatureFlagService:    localFeatureFlagService,
		Notifier:              localNotifier,
		LearnService:          localLearnService,
		LdxSyncService:        localLdxSyncService,
		ScanStateAggregator:   localScanStateAggregator,
		InlineValueProvider:   localInlineValueProvider,
		TreeEmitter:           nil,
		Scanner:               localScanner,
		HoverService:          localHoverService,
		ScanNotifier:          localScanNotifier,
		ScanPersister:         localScanPersister,
		FileWatcher:           localFileWatcher,
		ErrorReporter:         localErrorReporter,
		CodeActionService:     localCodeActionService,
		Installer:             localInstaller,
		CommandService:        localCommandService,
		ProgressChannel:       localProgressChannel,
	}
}

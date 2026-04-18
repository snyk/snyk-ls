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
	"github.com/snyk/snyk-ls/internal/types"
)

func TestInit(t *testing.T, engine workflow.Engine, tokenService types.TokenService) {
	t.Helper()
	initMutex.Lock()
	defer initMutex.Unlock()
	gafConfiguration := engine.GetConfiguration()
	gafConfiguration.Set(configresolver.UserGlobalKey(types.SettingCliPath), filepath.Join(t.TempDir(), "fake-cli"))
	types.DefaultOpenBrowserFunc = func(url string) {}
	notifier = domainNotify.NewNotifier()

	fs := pflag.NewFlagSet("snyk-ls-config-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConfiguration.AddFlagSet(fs)
	fm := workflow.ConfigurationOptionsFromFlagset(fs)

	logger := engine.GetLogger()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configresolver.New(gafConfiguration, fm)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConfiguration, fm)
	configResolver = resolver

	instrumentor = performance.NewInstrumentor()
	errorReporter = er.NewTestErrorReporter(engine)
	installer = install.NewFakeInstaller(engine, configResolver)
	authProvider := authentication.NewFakeCliAuthenticationProvider(engine)
	snykApiClient = &snyk_api.FakeApiClient{CodeEnabled: true}
	authenticationService = authentication.NewAuthenticationService(engine, tokenService, authProvider, errorReporter, notifier, configResolver)
	snykCli := cli.NewExecutor(engine, errorReporter, notifier, configResolver)
	cliInitializer = cli.NewInitializer(gafConfiguration, logger, errorReporter, installer, notifier, snykCli, configResolver)
	authInitializer := authentication.NewInitializer(gafConfiguration, logger, authenticationService, errorReporter, notifier, configResolver)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)

	codeInstrumentor = code.NewCodeInstrumentor()
	scanNotifier, _ = appNotification.NewScanNotifier(notifier, configResolver)
	ctrl := gomock.NewController(t)
	learnMock := mock_learn.NewMockService(ctrl)
	learnMock.EXPECT().GetAllLessons().Return([]learn.Lesson{{}}, nil).AnyTimes()
	learnMock.EXPECT().MaintainCacheFunc().AnyTimes()
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	learnService = learnMock
	scanPersister = persistence.NopScanPersister{}
	scanStateAggregator = scanstates.NewNoopStateAggregator()
	codeErrorReporter = code.NewCodeErrorReporter(errorReporter)
	featureFlagService = featureflag.New(gafConfiguration, logger, engine, configResolver)
	snykCodeScanner = code.New(engine, instrumentor, snykApiClient, codeErrorReporter, learnService, featureFlagService, notifier, codeInstrumentor, codeErrorReporter, code.NewFakeCodeScannerClient, configResolver)
	openSourceScanner = oss.NewCLIScanner(engine, instrumentor, errorReporter, snykCli, learnService, notifier, configResolver)
	infrastructureAsCodeScanner = iac.New(gafConfiguration, logger, instrumentor, errorReporter, snykCli, configResolver)
	scanner = scanner2.NewDelegatingScanner(engine, tokenService, scanInitializer, instrumentor, scanNotifier, snykApiClient, authenticationService, notifier, scanPersister, scanStateAggregator, configResolver, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	hoverService = hover.NewDefaultService(logger)
	ldxSyncService = command.NewLdxSyncService(configResolver, featureFlagService)
	mockCommandService := types.NewCommandServiceMock()
	command.SetService(mockCommandService)
	w := workspace.New(gafConfiguration, logger, instrumentor, scanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, configResolver, engine)
	config.SetWorkspace(gafConfiguration, w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(engine, w, fileWatcher, notifier, featureFlagService, configResolver)
}

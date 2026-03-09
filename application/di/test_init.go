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
	"github.com/snyk/go-application-framework/pkg/configuration"
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

func TestInit(t *testing.T) {
	t.Helper()
	initMutex.Lock()
	defer initMutex.Unlock()
	c := config.CurrentConfig()
	// we want to isolate CLI fake installs
	c.Engine().GetConfiguration().Set(configuration.UserGlobalKey(types.SettingCliPath), filepath.Join(t.TempDir(), "fake-cli"))
	// we don't want to open browsers when testing
	types.DefaultOpenBrowserFunc = func(url string) {}
	notifier = domainNotify.NewNotifier()

	gafConfiguration := c.Engine().GetConfiguration()
	fs := pflag.NewFlagSet("snyk-ls-config-test", pflag.ContinueOnError)
	types.RegisterAllConfigurations(fs)
	_ = gafConfiguration.AddFlagSet(fs)

	logger := c.Logger()
	resolver := types.NewConfigResolver(logger)
	prefixKeyResolver := configuration.NewConfigResolver(gafConfiguration)
	resolver.SetPrefixKeyResolver(prefixKeyResolver, gafConfiguration)
	configResolver = resolver

	instrumentor = performance.NewInstrumentor()
	errorReporter = er.NewTestErrorReporter(c)
	installer = install.NewFakeInstaller(c)
	authProvider := authentication.NewFakeCliAuthenticationProvider(c)
	snykApiClient = &snyk_api.FakeApiClient{CodeEnabled: true}
	authenticationService = authentication.NewAuthenticationService(c.Engine(), c.TokenService(), authProvider, errorReporter, notifier, c)
	snykCli := cli.NewExecutor(c, errorReporter, notifier)
	cliInitializer = cli.NewInitializer(gafConfiguration, logger, errorReporter, installer, notifier, snykCli)
	authInitializer := authentication.NewInitializer(gafConfiguration, logger, authenticationService, errorReporter, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)

	codeInstrumentor = code.NewCodeInstrumentor()
	scanNotifier, _ = appNotification.NewScanNotifier(notifier, configResolver)
	// mock Learn Service
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
	featureFlagService = featureflag.New(gafConfiguration, logger, c.Engine(), configResolver)
	snykCodeScanner = code.New(c, instrumentor, snykApiClient, codeErrorReporter, learnService, featureFlagService, notifier, codeInstrumentor, codeErrorReporter, code.NewFakeCodeScannerClient, configResolver)
	openSourceScanner = oss.NewCLIScanner(c.Engine(), instrumentor, errorReporter, snykCli, learnService, notifier, configResolver)
	infrastructureAsCodeScanner = iac.New(gafConfiguration, logger, instrumentor, errorReporter, snykCli, configResolver)
	scanner = scanner2.NewDelegatingScanner(c.Engine(), c.TokenService(), scanInitializer, instrumentor, scanNotifier, snykApiClient, authenticationService, notifier, scanPersister, scanStateAggregator, configResolver, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	hoverService = hover.NewDefaultService(c.Logger())
	ldxSyncService = command.NewLdxSyncService(configResolver)
	mockCommandService := types.NewCommandServiceMock()
	command.SetService(mockCommandService)
	// don't use getters or it'll deadlock
	w := workspace.New(gafConfiguration, logger, instrumentor, scanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator, featureFlagService, configResolver, c.Engine())
	c.SetWorkspace(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(c.Engine(), w, fileWatcher, notifier, featureFlagService, configResolver)
}

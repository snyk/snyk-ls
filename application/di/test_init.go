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
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	er "github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/domain/observability/ux"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	cliauth "github.com/snyk/snyk-ls/infrastructure/cli/auth"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/infrastructure/iac"
	"github.com/snyk/snyk-ls/infrastructure/learn"
	"github.com/snyk/snyk-ls/infrastructure/learn/mock_learn"
	"github.com/snyk/snyk-ls/infrastructure/oss"
	"github.com/snyk/snyk-ls/infrastructure/snyk_api"
	domainNotify "github.com/snyk/snyk-ls/internal/notification"
)

// TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	c := config.CurrentConfig()
	// we don't want to open browsers when testing
	snyk.DefaultOpenBrowserFunc = func(url string) {}
	notifier = domainNotify.NewNotifier()
	analytics = ux.NewTestAnalytics()
	instrumentor = performance.NewInstrumentor()
	errorReporter = er.NewTestErrorReporter()
	installer = install.NewFakeInstaller()
	authProvider := snyk.NewFakeCliAuthenticationProvider()
	snykApiClient = &snyk_api.FakeApiClient{CodeEnabled: true}
	authenticationService = snyk.NewAuthenticationService(authProvider, analytics, errorReporter, notifier)
	snykCli := cli.NewExecutor(authenticationService, errorReporter, analytics, notifier)
	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, snykCli)
	authInitializer := cliauth.NewInitializer(authenticationService, errorReporter, analytics, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
	fakeClient := &code.FakeSnykCodeClient{}
	snykCodeClient = fakeClient
	codeInstrumentor = code.NewCodeInstrumentor()
	snykCodeBundleUploader = code.NewBundler(snykCodeClient, codeInstrumentor)
	scanNotifier, _ = appNotification.NewScanNotifier(notifier)
	// mock Learn Service
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	learnService = learnMock
	snykCodeScanner = code.New(snykCodeBundleUploader, snykApiClient, errorReporter, analytics, learnService, notifier)
	openSourceScanner = oss.NewCLIScanner(instrumentor, errorReporter, analytics, snykCli, learnService, notifier, c)
	infrastructureAsCodeScanner = iac.New(instrumentor, errorReporter, analytics, snykCli)
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
	hoverService = hover.NewDefaultService(analytics)
	command.SetService(&snyk.CommandServiceMock{})
	// don't use getters or it'll deadlock
	w := workspace.New(instrumentor, scanner, hoverService, scanNotifier, notifier)
	workspace.Set(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(c, w, fileWatcher, notifier, snykCodeClient)
	t.Cleanup(
		func() {
			fakeClient.Clear()
		},
	)
}

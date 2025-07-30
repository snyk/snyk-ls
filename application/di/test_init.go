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

	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	scanner2 "github.com/snyk/snyk-ls/domain/snyk/scanner"

	"github.com/snyk/snyk-ls/application/codeaction"
	"github.com/snyk/snyk-ls/application/config"
	appNotification "github.com/snyk/snyk-ls/application/server/notification"
	"github.com/snyk/snyk-ls/application/watcher"
	"github.com/snyk/snyk-ls/domain/ide/command"
	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/initialize"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/cli"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/infrastructure/code"
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

// TODO this is becoming a hot mess we need to unify integ. test strategies
func TestInit(t *testing.T) {
	initMutex.Lock()
	defer initMutex.Unlock()
	t.Helper()
	c := config.CurrentConfig()
	// we want to isolate CLI fake installs
	c.CliSettings().SetPath(filepath.Join(t.TempDir(), "fake-cli"))
	// we don't want to open browsers when testing
	types.DefaultOpenBrowserFunc = func(url string) {}
	notifier = domainNotify.NewNotifier()
	instrumentor = performance.NewInstrumentor()
	errorReporter = er.NewTestErrorReporter()
	installer = install.NewFakeInstaller()
	authProvider := authentication.NewFakeCliAuthenticationProvider(c)
	snykApiClient = &snyk_api.FakeApiClient{CodeEnabled: true}
	authenticationService = authentication.NewAuthenticationService(c, authProvider, errorReporter, notifier)
	snykCli := cli.NewExecutor(c, errorReporter, notifier)
	cliInitializer = cli.NewInitializer(errorReporter, installer, notifier, snykCli)
	authInitializer := authentication.NewInitializer(c, authenticationService, errorReporter, notifier)
	scanInitializer = initialize.NewDelegatingInitializer(
		cliInitializer,
		authInitializer,
	)
	fakeClient := &code.FakeSnykCodeClient{C: c}
	snykCodeClient = fakeClient
	codeInstrumentor = code.NewCodeInstrumentor()
	snykCodeBundleUploader = code.NewBundler(c, snykCodeClient, codeInstrumentor)
	scanNotifier, _ = appNotification.NewScanNotifier(c, notifier)
	// mock Learn Service
	learnMock := mock_learn.NewMockService(gomock.NewController(t))
	learnMock.EXPECT().GetAllLessons().Return([]learn.Lesson{{}}, nil).AnyTimes()
	learnMock.EXPECT().MaintainCache().AnyTimes()
	learnMock.
		EXPECT().
		GetLesson(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&learn.Lesson{}, nil).AnyTimes()
	learnService = learnMock
	codeClientScanner := &code.FakeCodeScannerClient{}
	scanPersister = persistence.NopScanPersister{}
	scanStateAggregator = scanstates.NewNoopStateAggregator()
	codeErrorReporter = code.NewCodeErrorReporter(errorReporter)
	snykCodeScanner = code.New(snykCodeBundleUploader, snykApiClient, codeErrorReporter, learnService, notifier, codeClientScanner)
	openSourceScanner = oss.NewCLIScanner(c, instrumentor, errorReporter, snykCli, learnService, notifier)
	infrastructureAsCodeScanner = iac.New(c, instrumentor, errorReporter, snykCli)
	scanner = scanner2.NewDelegatingScanner(c, scanInitializer, instrumentor, scanNotifier, snykApiClient, authenticationService, notifier, scanPersister, scanStateAggregator, snykCodeScanner, infrastructureAsCodeScanner, openSourceScanner)
	hoverService = hover.NewDefaultService(c)
	command.SetService(&types.CommandServiceMock{})
	// don't use getters or it'll deadlock
	w := workspace.New(c, instrumentor, scanner, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)
	c.SetWorkspace(w)
	fileWatcher = watcher.NewFileWatcher()
	codeActionService = codeaction.NewService(c, w, fileWatcher, notifier, snykCodeClient)
	t.Cleanup(
		func() {
			fakeClient.Clear()
		},
	)
}

/*
 * © 2022 Snyk Limited All rights reserved.
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

package codelens

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/infrastructure/authentication"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_GetCodeLensFromCommand(t *testing.T) {
	testutil.UnitTest(t)
	issue := code.FakeIssue
	command := code.FakeCommand
	codeLens := getCodeLensFromCommand(issue.Range, command)
	assert.Equal(t, converter.ToRange(issue.Range), codeLens.Range)
	assert.Equal(t, command.CommandId, codeLens.Command.Command)
	assert.Equal(t, command.Title, codeLens.Command.Title)
	assert.Equal(t, command.Arguments, codeLens.Command.Arguments)
}

func Test_GetCodeLensForPath(t *testing.T) {
	c := testutil.IntegTest(t)
	di.TestInit(t) // IntegTest doesn't automatically inits DI
	testutil.EnableSastAndAutoFix(c)
	// this is using the real progress channel, so we need to listen to it
	dummyProgressListeners(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	filePath, dir := code.TempWorkdirWithIssues(t)
	folder := workspace.NewFolder(c, dir, "dummy", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator(), di.FeatureFlagService())
	c.Workspace().AddFolder(folder)

	// as code is only enabled if sast settings are enabled, and sast settings are checked in folder config
	// and sast settings are added in the `testutil.OnlyEnableCode` function, we need to call it after
	// adding the workspace folder
	testutil.OnlyEnableCode(t, c)

	folder.ScanFile(t.Context(), filePath)

	if folder.IssuesForFile(filePath) == nil {
		t.Fatal("issues for file should not be nil")
	}

	lenses := GetFor(filePath)

	if lenses == nil {
		t.Fatal("lenses should not be nil")
	}
	assert.Equal(t, 1, len(lenses))
	assert.Equal(t, lenses[0].Command.Title, code.FixIssuePrefix+code.DontUsePrintStackTrace)
}

func dummyProgressListeners(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { progress.CleanupChannels() })
	go func() {
		for {
			<-progress.ToServerProgressChannel
		}
	}()
}

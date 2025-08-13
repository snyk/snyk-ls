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

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
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
	testutil.OnlyEnableCode()
	// Because the scan results are being provided by code.getSarifResponseJson2, we need to enable autofix so that issues
	// get enhanced with commands (see code.addIssueActions).
	c.Engine().GetConfiguration().Set(
		code_workflow.ConfigurationSastSettings,
		&sast_contract.SastResponse{SastEnabled: true, AutofixEnabled: true},
	)
	// this is using the real progress channel, so we need to listen to it
	dummyProgressListeners(t)

	fakeAuthenticationProvider := di.AuthenticationService().Provider().(*authentication.FakeAuthenticationProvider)
	fakeAuthenticationProvider.IsAuthenticated = true

	filePath, dir := code.TempWorkdirWithIssues(t)
	folder := workspace.NewFolder(c, dir, "dummy", di.Scanner(), di.HoverService(), di.ScanNotifier(), di.Notifier(), di.ScanPersister(), di.ScanStateAggregator())
	c.Workspace().AddFolder(folder)
	folder.ScanFile(t.Context(), filePath)

	assert.NotNil(t, folder.IssuesForFile(filePath))

	lenses := GetFor(filePath)

	assert.NotNil(t, lenses)
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

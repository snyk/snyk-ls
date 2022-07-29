package codelens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/di"
	"github.com/snyk/snyk-ls/domain/ide/converter"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/observability/performance"
	"github.com/snyk/snyk-ls/infrastructure/code"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_GetCodeLensFromCommand(t *testing.T) {
	testutil.UnitTest(t)
	issue := code.FakeIssue
	command := code.FakeCommand
	codeLens := getCodeLensFromCommand(issue, command)
	assert.Equal(t, converter.ToRange(issue.Range), codeLens.Range)
	assert.Equal(t, command.Command, codeLens.Command.Command)
	assert.Equal(t, command.Title, codeLens.Command.Title)
	assert.Equal(t, command.Arguments, codeLens.Command.Arguments)
}

func TestGetFor(t *testing.T) {
	testutil.UnitTest(t)
	di.TestInit(t)
	testutil.OnlyEnableCodeAndDisableBinaryManagement()
	filePath, dir := code.FakeDiagnosticPath()
	folder := workspace.NewFolder(dir, "dummy", di.Scanner(), di.HoverService())
	workspace.Set(workspace.New(performance.NewTestInstrumentor()))
	workspace.Get().AddFolder(folder)
	folder.ScanFile(context.Background(), filePath)

	assert.Eventually(t, func() bool {
		return folder.DocumentDiagnosticsFromCache(filePath) != nil
	}, time.Second*2, time.Millisecond)

	lenses := GetFor(filePath)

	assert.NotNil(t, lenses)
	assert.Equal(t, 1, len(lenses))
	assert.Equal(t, code.FakeCommand.Command, lenses[0].Command.Command)
}

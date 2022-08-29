package codeaction

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

func TestGetFor(t *testing.T) {
	testutil.IntegTest(t)
	di.TestInit(t)
	testutil.OnlyEnableCodeAndDisableBinaryManagement()

	filePath, dir := code.FakeDiagnosticPath(t)
	folder := workspace.NewFolder(dir, "dummy", di.Scanner(), di.HoverService())
	workspace.Set(workspace.New(performance.NewTestInstrumentor()))
	workspace.Get().AddFolder(folder)
	go folder.ScanFile(context.Background(), filePath)

	assert.Eventually(t, func() bool {
		return folder.DocumentDiagnosticsFromCache(filePath) != nil
	}, time.Second*2, time.Millisecond)

	actions := GetFor(filePath, converter.ToRange(code.FakeIssue.Range))

	assert.NotNil(t, actions)
	assert.Equal(t, 1, len(actions))
	assert.Equal(t, code.FakeCommand.Command, actions[0].Command.Command)
}

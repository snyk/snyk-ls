/*
 * Copyright 2022 Snyk Ltd.
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

package codeaction

import (
	"context"
	"testing"

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
	workspace.Set(workspace.New(performance.NewTestInstrumentor(), di.Scanner(), di.HoverService()))
	workspace.Get().AddFolder(folder)
	folder.ScanFile(context.Background(), filePath)

	assert.NotNil(t, folder.DocumentDiagnosticsFromCache(filePath))

	actions := GetFor(filePath, converter.ToRange(code.FakeIssue.Range))

	assert.NotNil(t, actions)
	assert.Equal(t, 1, len(actions))
	assert.Equal(t, code.FakeCommand.Command, actions[0].Command.Command)
}

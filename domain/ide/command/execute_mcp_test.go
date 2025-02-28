//go:build !race
// +build !race

/*
 * © 2024 Snyk Limited
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

package command

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/domain/ide/hover"
	"github.com/snyk/snyk-ls/domain/ide/workspace"
	"github.com/snyk/snyk-ls/domain/scanstates"
	"github.com/snyk/snyk-ls/domain/snyk/persistence"
	"github.com/snyk/snyk-ls/domain/snyk/scanner"
	"github.com/snyk/snyk-ls/internal/mcp"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/performance"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func Test_executeMcpCallCommand(t *testing.T) {
	c := testutil.UnitTest(t)
	c.SetAutomaticScanning(false)

	// start mcp server
	sc := scanner.NewTestScanner()
	scanNotifier := scanner.NewMockScanNotifier()
	hoverService := hover.NewFakeHoverService()
	notifier := noti.NewMockNotifier()
	emitter := scanstates.NewSummaryEmitter(c, notifier)
	scanStateAggregator := scanstates.NewScanStateAggregator(c, emitter)
	scanPersister := persistence.NewNopScanPersister()
	w := workspace.New(c, performance.NewInstrumentor(), sc, hoverService, scanNotifier, notifier, scanPersister, scanStateAggregator)

	f := workspace.NewFolder(
		c,
		"testPath",
		"test",
		sc,
		hoverService,
		scanNotifier,
		notifier,
		scanPersister,
		scanStateAggregator,
	)

	w.AddFolder(f)
	c.SetWorkspace(w)

	mcpBinding := mcp.NewMcpLLMBinding(c, mcp.WithLogger(c.Logger()), mcp.WithScanner(sc))
	go func() {
		_ = mcpBinding.Start()
	}()

	t.Cleanup(func() {
		timeout, cancelFunc := context.WithTimeout(context.Background(), time.Second)
		mcpBinding.Shutdown(timeout)
		defer cancelFunc()
	})

	// wait for mcp server to start
	assert.Eventually(t, func() bool {
		return mcpBinding.Started()
	}, time.Minute, time.Millisecond)

	// create command
	command := executeMcpCallCommand{
		command: types.CommandData{
			Title:     "Execute Snyk Scan",
			CommandId: types.ExecuteMCPToolCall,
			Arguments: []any{mcp.SnykScanWorkspaceScan},
		},
		notifier: noti.NewMockNotifier(),
		logger:   c.Logger(),
		baseURL:  c.GetMCPServerURL().String(),
	}

	// execute command
	_, err := command.Execute(context.Background())
	require.NoError(t, err)
	require.Eventuallyf(t, func() bool {
		return sc.Calls() > 0
	}, time.Minute, time.Millisecond, "should have called the scanner")
}

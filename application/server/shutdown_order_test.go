/*
 * © 2026 Snyk Limited
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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ctx2 "github.com/snyk/snyk-ls/internal/context"
	"github.com/snyk/snyk-ls/internal/notification"
	er "github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// Shutdown must cancel the writers before it stops the reader: scanners send to
// the progress channel with an unguarded write, so stopping the listener while
// scans are still in flight leaves only the channel buffer between a scan and a
// permanent block.
func Test_Shutdown_CancelsScansBeforeStoppingProgressListener(t *testing.T) {
	engine := testutil.UnitTest(t)
	logger := engine.GetLogger()

	ctx := ctx2.NewContextWithLogger(t.Context(), logger)
	ctx = ctx2.NewContextWithDependencies(ctx, map[string]any{
		ctx2.DepNotifier:      notification.NewNotifier(),
		ctx2.DepErrorReporter: er.NewTestErrorReporter(engine),
	})

	progressStopChan := make(chan bool, 1)
	listenerStoppedFirst := false
	scanCanceled := false
	scanCancel := func() {
		scanCanceled = true
		listenerStoppedFirst = len(progressStopChan) > 0
	}

	require.NoError(t, shutdown(ctx, progressStopChan, scanCancel, nil, &backgroundInit{}))

	require.True(t, scanCanceled, "shutdown must cancel the scan context")
	assert.False(t, listenerStoppedFirst,
		"in-flight scans must be canceled BEFORE the progress listener is stopped, otherwise a scan can block forever on a full progress channel")
	assert.Len(t, progressStopChan, 1, "the progress listener must still be stopped")
}

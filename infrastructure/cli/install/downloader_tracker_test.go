/*
 * © 2026 Snyk Limited All rights reserved.
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

package install

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestNewDownloader_RoutesToInjectedTrackerChannel(t *testing.T) {
	engine := testutil.UnitTest(t)
	logger := zerolog.Nop()

	tracker := progress.NewTracker(&logger)

	d := NewDownloader(engine, nil, nil, tracker)

	require.NotNil(t, d.progressTask, "progressTask must be set")
	assert.Equal(t, tracker.Channel(), d.progressTask.GetChannel(),
		"progressTask's channel must be the tracker's channel")
}

// The installer must thread its injected tracker into every downloader it builds,
// otherwise download progress goes to a channel nothing drains.
func TestInstall_NewDownloader_RoutesToInjectedTrackerChannel(t *testing.T) {
	engine := testutil.UnitTest(t)
	tracker := testutil.NewDrainedProgressTracker()

	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.DefaultConfigResolver(engine), tracker)

	d := i.newDownloader()

	require.NotNil(t, d.progressTask, "progressTask must be set")
	assert.Equal(t, tracker.Channel(), d.progressTask.GetChannel(),
		"the installer-produced downloader must route to the injected tracker's channel")
}

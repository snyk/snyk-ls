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

	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// UNIT-112 (IDE-2036): NewDownloader routes progress events to the owner
// channel supplied at construction rather than the global ToServerProgressChannel.
func TestNewDownloader_RoutesToInjectedOwnerChannel(t *testing.T) {
	engine := testutil.UnitTest(t)
	logger := zerolog.Nop()

	owner := progress.NewTracker(&logger)

	// NewDownloader must accept an *Owner and use owner.New(true) as the
	// progressTracker field so that progress events reach owner.Channel().
	d := NewDownloaderWithOwner(engine, nil, nil, testutil.DefaultConfigResolver(engine), owner)

	// The downloader's internal task must route to the owner's channel.
	require.NotNil(t, d.progressTask, "progressTask must be set")
	assert.Equal(t, owner.Channel(), d.progressTask.GetChannel(),
		"progressTask's channel must be the owner's channel")
}

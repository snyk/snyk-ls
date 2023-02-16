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

package install

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

type mockProgressHandler struct {
	mock.Mock
}

func (p *mockProgressHandler) Handle(params lsp.ProgressParams) {
	p.Called(params)
}

func TestDownloader_Download(t *testing.T) {
	testutil.IntegTest(t)
	r := getTestAsset()

	ph := mockProgressHandler{}
	ph.On("Handle", mock.Anything).Return()
	progressTracker := progress.NewTestTracker()
	progress.ProgressReported.Subscribe(&ph)
	d := &Downloader{progressTracker: progressTracker}
	lockFileName := d.lockFileName()
	_ = os.RemoveAll(lockFileName) // remove any existing lockfile

	err := d.Download(r, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, ph.Mock.Calls)
	assert.True(t, len(ph.Mock.Calls) >= 3) // has at least started, reported & finished progress

	//make sure cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		_ = os.RemoveAll(lockFileName)
	}
	assert.Error(t, err)
}

func Test_DoNotDownloadIfCancelled(t *testing.T) {
	testutil.UnitTest(t)
	tracker := progress.NewTestTracker()
	d := &Downloader{progressTracker: tracker}
	r := getTestAsset()

	// simulate cancellation when some progress received
	ph := &mockProgressHandler{}
	ph.On("Handle", mock.Anything).Run(func(args mock.Arguments) {
		progress.ProgressCancelled.Raise(tracker.GetToken()) // Send cancel signal when progress received
	})
	progress.ProgressReported.Subscribe(ph)
	t.Cleanup(func() { _ = progress.ProgressReported.Unsubscribe(ph) })

	err := d.Download(r, false)

	assert.Error(t, err)

	// make sure cancellation cleanup works
	_, err = os.Stat(config.CurrentConfig().CLIDownloadLockFileName())
	if err == nil {
		assert.Error(t, err)
	}
}

func getTestAsset() *Release {
	r := &Release{
		Assets: &ReleaseAssets{
			MacOS: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.912.0/snyk-macos",
				ChecksumInfo: "c5761b9704bfe8d793001cd183cd84d39c12ca5cad674758aa3b747ec73d8df8  snyk-macos",
			},
			Linux: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.912.0/snyk-linux",
				ChecksumInfo: "956027e8f417df8203da7e614045a7255de0da418ae3ce4664b8eb6fba7b392b  snyk-linux",
			},
			LinuxARM64: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.912.0/snyk-linux-arm64",
				ChecksumInfo: "2b0a8eff7a25bf169dd3397a8e4870867b21a512ca2da47c4f83b04e40098245  snyk-linux-arm64",
			},
			Windows: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.912.0/snyk-win.exe",
				ChecksumInfo: "c3efd52d44521c424cfbac7934ec90eff57ea181f8d3c002b7a007748f8599b7  snyk-win.exe",
			},
		},
	}
	return r
}

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
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/lsp"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestDownloader_Download(t *testing.T) {
	testutil.IntegTest(t)
	r := getTestAsset()
	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh),
		httpClient:      func() *http.Client { return http.DefaultClient },
	}
	exec := (&Discovery{}).ExecutableName(false)
	destination := filepath.Join(t.TempDir(), exec)
	config.CurrentConfig().CliSettings().SetPath(destination)
	lockFileName := d.lockFileName()
	// remove any existing lockfile
	_ = os.RemoveAll(lockFileName)

	err := d.Download(r, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, progressCh)
	assert.True(t, len(progressCh) >= 3) // has at least started, reported & finished progress

	//make sure cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		_ = os.RemoveAll(lockFileName)
	}
	assert.Error(t, err)
}

func Test_DoNotDownloadIfCancelled(t *testing.T) {
	testutil.UnitTest(t)
	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh),
		httpClient:      func() *http.Client { return http.DefaultClient },
	}

	r := getTestAsset()

	// simulate cancellation when some progress received
	go func() {
		prog := <-progressCh
		cancelProgressCh <- prog.Token
	}()

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
				URL:          "https://static.snyk.io/cli/v1.1276.0/snyk-macos",
				ChecksumInfo: "00c7f96ce389cff3f79e920ba345efef2ab78f80ffebd8922082dfca07ed3af0  snyk-macos",
			},
			MacOSARM64: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.1276.0/snyk-macos-arm64",
				ChecksumInfo: "691b455a8fdcfb31089ca460658d060b51c58b2e37dc757e8b5434ca0a9b80cf  snyk-macos-arm64",
			},
			Linux: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.1276.0/snyk-linux",
				ChecksumInfo: "4ade26062f3631bf04ca6a75a7c560752585d2aed025a6a4be97517dbb4701ce  snyk-linux",
			},
			LinuxARM64: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.1276.0/snyk-linux-arm64",
				ChecksumInfo: "c26cc7e49354c24d4eeaec41445c612f3b93ad782482fbf9f7d38947815f01a8  snyk-linux-arm64",
			},
			Windows: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.1276.0/snyk-win.exe",
				ChecksumInfo: "76f38b24fe996dcdcb6750f005f2f07044c7a01b7f355d59f88104611a2c9d65  snyk-win.exe",
			},
		},
	}
	return r
}

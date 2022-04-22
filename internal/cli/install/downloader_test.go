package install

import (
	"os"
	"testing"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/lsp"

	"github.com/stretchr/testify/assert"
)

var progressCh = make(chan lsp.ProgressParams, 1000)
var progressCancelCh = make(chan lsp.ProgressToken, 1)

func TestDownloader_Download(t *testing.T) {
	testutil.IntegTest(t)
	Mutex.Lock()
	defer Mutex.Unlock()
	r := getTestAsset()
	d := &Downloader{}

	lockFileName, err := d.lockFileName()
	if err != nil {
		t.Fatal(err)
	}
	// remove any existing lockfile
	_ = os.RemoveAll(lockFileName)

	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)

	err = d.Download(r, progressCh, cancelProgressCh)

	assert.NoError(t, err)
	assert.NotEmpty(t, progressCh)
	assert.True(t, len(progressCh) > 3) // has at least started, reported & finished progress

	//make sure cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		os.RemoveAll(lockFileName)
	}
	assert.Error(t, err)
}

func Test_DoNotDownloadIfLockfileFound(t *testing.T) {
	Mutex.Lock()
	defer Mutex.Unlock()
	r := getTestAsset()
	d := &Downloader{}

	lockFileName, err := d.lockFileName()
	if err != nil {
		log.Fatal().Err(err).Msg("error getting logfile name")
	}
	_, err = os.Create(lockFileName)
	if err != nil {
		t.Fatal("couldn't create lockfile")
	}
	defer func(name string) {
		_ = os.RemoveAll(name)
	}(lockFileName)

	err = d.Download(r, progressCh, progressCancelCh)

	assert.Error(t, err)
}

func Test_DoNotDownloadIfCancelled(t *testing.T) {
	Mutex.Lock()
	defer Mutex.Unlock()
	r := getTestAsset()
	d := &Downloader{}

	lockFileName, err := d.lockFileName()
	if err != nil {
		t.Fatal(err)
	}
	// remove any existing lockfile
	_ = os.RemoveAll(lockFileName)

	progressCh := make(chan lsp.ProgressParams, 100000)
	cancelProgressCh := make(chan lsp.ProgressToken, 1)

	// simulate cancellation when some progress received
	go func() {
		prog := <-progressCh
		cancelProgressCh <- prog.Token
	}()

	err = d.Download(r, progressCh, cancelProgressCh)

	assert.Error(t, err)

	// make sure cancellation cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		os.RemoveAll(lockFileName)
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

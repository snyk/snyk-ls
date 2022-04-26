package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloader_Download(t *testing.T) {
	//testutil.IntegTest(t)

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

	d := &Downloader{}
	err := d.Download(r)

	assert.NoError(t, err)
}

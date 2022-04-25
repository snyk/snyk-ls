package install

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestDownloader_Download(t *testing.T) {
	testutil.IntegTest(t)

	r := &Release{
		Assets: &ReleaseAssets{
			MacOS: &ReleaseAsset{
				URL:          "https://static.snyk.io/cli/v1.906.0/snyk-macos",
				ChecksumInfo: "89f8e03e185d1e1994ae90035d3842019b19978607a15f1fe648f725601fbb7a  snyk-macos",
			},
		},
	}

	d := &Downloader{}
	err := d.Download(r)

	assert.NoError(t, err)
}

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
				URL:         "https://static.snyk.io/cli/v1.906.0/snyk-macos",
				ChecksumURL: "https://static.snyk.io/cli/v1.906.0/snyk-macos.sha256",
			},
		},
	}

	d := &Downloader{}
	err := d.Download(r)

	assert.NoError(t, err)
}

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiscovery_DownloadURL(t *testing.T) {
	d := &Discovery{}
	r := &Release{
		Assets: &ReleaseAssets{
			AlpineLinux: &ReleaseAsset{
				URL: "alpine-download-url",
			},
			Linux: &ReleaseAsset{
				URL: "linux-download-url",
			},
			LinuxARM64: &ReleaseAsset{
				URL: "linux-arm64-download-url",
			},
			MacOS: &ReleaseAsset{
				URL: "macos-download-url",
			},
			Windows: &ReleaseAsset{
				URL: "windows-download-url",
			},
		},
	}

	url, err := d.DownloadURL(r)

	assert.NoError(t, err)
	assert.NotEmpty(t, url)
}

func TestDiscovery_ChecksumURL(t *testing.T) {
	d := &Discovery{}
	r := &Release{
		Assets: &ReleaseAssets{
			AlpineLinux: &ReleaseAsset{
				ChecksumURL: "alpine-checksum-url",
			},
			Linux: &ReleaseAsset{
				ChecksumURL: "linux-checksum-url",
			},
			LinuxARM64: &ReleaseAsset{
				ChecksumURL: "linux-arm64-checksum-url",
			},
			MacOS: &ReleaseAsset{
				ChecksumURL: "macos-checksum-url",
			},
			Windows: &ReleaseAsset{
				ChecksumURL: "windows-checksum-url",
			},
		},
	}

	url, err := d.ChecksumURL(r)

	assert.NoError(t, err)
	assert.NotEmpty(t, url)
}

func TestDiscovery_DownloadURL_nilRelease(t *testing.T) {
	d := &Discovery{}

	url, err := d.DownloadURL(nil)

	assert.Error(t, err)
	assert.Empty(t, url)
}

func TestDiscovery_ChecksumURL_nilRelease(t *testing.T) {
	d := &Discovery{}

	url, err := d.ChecksumURL(nil)

	assert.Error(t, err)
	assert.Empty(t, url)
}

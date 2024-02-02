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
			MacOSARM64: &ReleaseAsset{
				URL: "macos-arm64-download-url",
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
			MacOSARM64: &ReleaseAsset{
				ChecksumURL: "macos-arm64-checksum-url",
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

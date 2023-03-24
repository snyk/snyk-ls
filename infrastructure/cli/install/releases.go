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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

const defaultBaseURL = "https://static.snyk.io"

// Release represents a Snyk CLI release with assets.
type Release struct {
	Version string         `json:"version,omitempty"`
	Assets  *ReleaseAssets `json:"assets,omitempty"`
}

// ReleaseAssets represents a assets object.
type ReleaseAssets struct {
	AlpineLinux *ReleaseAsset `json:"snyk-alpine,omitempty"`
	Linux       *ReleaseAsset `json:"snyk-linux,omitempty"`
	LinuxARM64  *ReleaseAsset `json:"snyk-linux-arm64,omitempty"`
	MacOS       *ReleaseAsset `json:"snyk-macos,omitempty"`
	Windows     *ReleaseAsset `json:"snyk-win.exe,omitempty"`
}

// ReleaseAsset represents a Snyk CLI release asset including url to CLI binary and sha256 checksum.
type ReleaseAsset struct {
	URL          string `json:"url,omitempty"`
	ChecksumInfo string `json:"sha256,omitempty"`
	ChecksumURL  string `json:"sha256Url,omitempty"`
}

type CLIRelease struct {
	baseURL    string
	httpClient func() *http.Client
}

func NewCLIRelease(httpClient func() *http.Client) *CLIRelease {
	return &CLIRelease{
		baseURL:    defaultBaseURL,
		httpClient: httpClient,
	}
}

func (r *CLIRelease) GetLatestRelease(ctx context.Context) (*Release, error) {
	releaseURL := fmt.Sprintf("%s/cli/latest/release.json", r.baseURL)
	log.Ctx(ctx).Trace().Str("url", releaseURL).Msg("requesting version for Snyk CLI")

	resp, err := r.httpClient().Get(releaseURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to obtained Snyk CLI release from %q: %s ", releaseURL, resp.Status)
	}

	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)

	log.Ctx(ctx).Trace().Str("response_status", resp.Status).Msg("received")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	p := Release{}
	err = json.Unmarshal(body, &p)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal: %q", err, string(body))
	}

	return &p, nil
}

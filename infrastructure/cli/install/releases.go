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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"

	http2 "github.com/snyk/code-client-go/http"

	"github.com/snyk/snyk-ls/application/config"
)

const DefaultBaseURL = "https://static.snyk.io"

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
	MacOSARM64  *ReleaseAsset `json:"snyk-macos-arm64,omitempty"`
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

type LSReleaseMetadata struct {
	ProjectName string    `json:"project_name"`
	Tag         string    `json:"tag"`
	PreviousTag string    `json:"previous_tag"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	Date        time.Time `json:"date"`
}

func NewCLIRelease(httpClient func() *http.Client) *CLIRelease {
	return &CLIRelease{
		baseURL:    DefaultBaseURL,
		httpClient: httpClient,
	}
}

func (r *CLIRelease) GetLatestReleaseByChannel(releaseChannel string, fipsAvailable bool) (*Release, error) {
	logger := config.CurrentConfig().Logger()
	baseURL := getBaseURL(r.baseURL, fipsAvailable)
	releaseURL := fmt.Sprintf("%s/cli/%s/release.json", baseURL, releaseChannel)
	logger.Trace().Str("url", releaseURL).Msg("requesting version for Snyk CLI")

	resp, err := r.httpClient().Get(releaseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to obtained Snyk CLI release from %q: %s ", releaseURL, resp.Status)
	}

	logger.Trace().Str("response_status", resp.Status).Msg("received")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	p := Release{}
	err = json.Unmarshal(body, &p)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to unmarshal: %q", err, string(body))
	}

	return &p, nil
}

func getBaseURL(baseURL string, fipsAvailable bool) string {
	if fipsAvailable {
		baseURL = path.Join(DefaultBaseURL, "/fips")
	}
	return baseURL
}

func (r *CLIRelease) GetLatestRelease() (*Release, error) {
	return r.GetLatestReleaseByChannel("latest", false)
}

func getDistributionChannel(c *config.Config) string {
	info := c.Engine().GetRuntimeInfo()
	if info == nil {
		return "stable"
	}
	version := info.GetVersion()
	if strings.Contains(version, "-preview.") {
		return "preview"
	}
	if strings.Contains(version, "-rc.") {
		return "rc"
	}
	return "stable"
}

func GetCLIDownloadURL(c *config.Config, baseURL string, httpClient http2.HTTPClient) string {
	logger := c.Logger().With().Str("method", "getCLIDownloadURL").Logger()
	defaultFallBack := "https://github.com/snyk/cli/releases"
	releaseChannel := getDistributionChannel(c)
	versionURL := fmt.Sprintf("%s/cli/%s/ls-protocol-version-%s", baseURL, releaseChannel, config.LsProtocolVersion)

	logger.Debug().Str("versionURL", versionURL).Msg("determined base version URL")

	bodyReader := &bytes.Buffer{}
	req, err := http.NewRequest(http.MethodGet, versionURL, bodyReader)
	if err != nil {
		logger.Err(err).Msg("could not create request to retrieve CLI version")
		return defaultFallBack
	}

	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode >= http.StatusBadRequest {
		logger.Err(errors.Wrap(err, "couldn't get version of CLI that supports current protocol version"))
		return defaultFallBack
	}
	defer resp.Body.Close()

	versionBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Err(errors.Wrap(err, "couldn't get version of CLI that supports current protocol version"))
		return defaultFallBack
	}

	version := string(versionBytes)
	logger.Debug().Str("version", version).Msg("retrieved version from web")

	discovery := Discovery{}
	downloadURL := fmt.Sprintf("%s/cli/v%s/%s", baseURL, version, discovery.ExecutableName(false))
	return downloadURL
}

func GetLSDownloadURL(c *config.Config, httpClient http2.HTTPClient) string {
	logger := c.Logger().With().Str("method", "GetLSDownloadURL").Logger()
	defaultFallBack := "https://github.com/snyk/snyk-ls/releases"
	baseURL := fmt.Sprintf("https://static.snyk.io/snyk-ls/%s", config.LsProtocolVersion)
	metadataURL := fmt.Sprintf("%s/metadata.json", baseURL)
	bodyReader := &bytes.Buffer{}

	req, err := http.NewRequest(http.MethodGet, metadataURL, bodyReader)
	if err != nil {
		logger.Err(err).Msg("couldn't create request")
		return defaultFallBack
	}

	response, err := httpClient.Do(req)
	if err != nil {
		logger.Err(err).Msg("couldn't get metadata for download")
		return defaultFallBack
	}

	if response.StatusCode >= http.StatusBadRequest {
		logger.Error().
			Int("statusCode", response.StatusCode).
			Str("status", response.Status).
			Msg("http request returned error status code")
		return defaultFallBack
	}
	defer response.Body.Close()

	metadataJson, err := io.ReadAll(response.Body)
	if err != nil {
		logger.Err(err).Msg("couldn't read response body")
	}

	var metadata LSReleaseMetadata
	err = json.Unmarshal(metadataJson, &metadata)
	if err != nil {
		logger.Err(err).Str("metadata", string(metadataJson)).Msg("couldn't unmarshall metadata")
		return defaultFallBack
	}
	exeIfNeeded := ""
	if runtime.GOOS == "windows" {
		exeIfNeeded = ".exe"
	}
	downloadURL := fmt.Sprintf("%s/snyk-ls_%s_%s_%s%s", baseURL, metadata.Version, runtime.GOOS, runtime.GOARCH, exeIfNeeded)

	return downloadURL
}

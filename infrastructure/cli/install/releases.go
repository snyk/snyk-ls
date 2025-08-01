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

	http2 "github.com/snyk/code-client-go/http"

	"github.com/snyk/snyk-ls/application/config"
)

const DefaultBaseURL = "https://downloads.snyk.io"

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
	logger := c.Logger().With().Str("method", "getDistributionChannel").Logger()
	info := c.Engine().GetRuntimeInfo()
	if info == nil {
		logger.Debug().Msg("no runtime info, assuming stable")
		return "stable"
	}
	version := info.GetVersion()
	logger.Debug().Str("runtimeVersion", version).Msg("checking version")
	if strings.Contains(version, "-preview.") {
		logger.Debug().Msg("using preview channel")
		return "preview"
	}
	if strings.Contains(version, "-rc.") {
		logger.Debug().Msg("using rc channel")
		return "rc"
	}
	logger.Debug().Msg("not rc or preview, using stable channel")
	return "stable"
}

func GetCLIDownloadURL(c *config.Config, baseURL string, httpClient http2.HTTPClient) string {
	return GetCLIDownloadURLForProtocol(c, baseURL, httpClient, config.LsProtocolVersion)
}

func GetLSDownloadURL(c *config.Config, httpClient http2.HTTPClient) string {
	return GetLSDownloadURLForProtocol(c, httpClient, config.LsProtocolVersion)
}

// GetCLIDownloadURLForProtocol returns the CLI download URL for a specific protocol version
func GetCLIDownloadURLForProtocol(c *config.Config, baseURL string, httpClient http2.HTTPClient, protocolVersion string) string {
	logger := c.Logger().With().Str("method", "getCLIDownloadURLForProtocol").Logger()
	defaultFallBack := "https://github.com/snyk/cli/releases"
	releaseChannel := getDistributionChannel(c)
	versionURL := fmt.Sprintf("%s/cli/%s/ls-protocol-version-%s", baseURL, releaseChannel, protocolVersion)

	logger.Debug().Str("versionURL", versionURL).Msg("determined base version URL")

	bodyReader := &bytes.Buffer{}
	req, err := http.NewRequest(http.MethodGet, versionURL, bodyReader)
	if err != nil {
		logger.Err(err).Str("versionURL", versionURL).Msg("could not create request to retrieve CLI version")
		return defaultFallBack
	}

	resp, err := httpClient.Do(req)
	if err != nil || resp.StatusCode >= http.StatusBadRequest {
		logger.Err(err).Str("versionURL", versionURL).Msg("couldn't get version of CLI that supports the protocol version")
		return defaultFallBack
	}
	defer resp.Body.Close()

	versionBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Err(err).Str("versionURL", versionURL).Msg("couldn't get version of CLI that supports the protocol version")
		return defaultFallBack
	}

	version := string(versionBytes)
	logger.Debug().Str("version", version).Msg("retrieved version from web")

	discovery := Discovery{}
	downloadURL := fmt.Sprintf("%s/cli/v%s/%s", baseURL, version, discovery.ExecutableName(false))
	return downloadURL
}

// GetLSDownloadURLForProtocol returns the LS download URL for a specific protocol version
func GetLSDownloadURLForProtocol(c *config.Config, httpClient http2.HTTPClient, protocolVersion string) string {
	logger := c.Logger().With().Str("method", "GetLSDownloadURLForProtocol").Logger()
	logger.Debug().Str("protocolVersion", protocolVersion).Msg("getting LS download URL for protocol version")
	defaultFallBack := "https://github.com/snyk/snyk-ls/releases"
	baseURL := fmt.Sprintf("https://static.snyk.io/snyk-ls/%s", protocolVersion)
	metadataURL := fmt.Sprintf("%s/metadata.json", baseURL)
	bodyReader := &bytes.Buffer{}

	req, err := http.NewRequest(http.MethodGet, metadataURL, bodyReader)
	if err != nil {
		logger.Err(err).Msg("couldn't create request")
		return defaultFallBack
	}

	response, err := httpClient.Do(req)
	if err != nil {
		logger.Err(err).Str("protocolVersion", protocolVersion).Msg("couldn't get metadata for download")
		return defaultFallBack
	}

	if response.StatusCode >= http.StatusBadRequest {
		logger.Error().
			Int("statusCode", response.StatusCode).
			Str("status", response.Status).
			Str("protocolVersion", protocolVersion).
			Msg("http request returned error status code")
		return defaultFallBack
	}
	defer response.Body.Close()

	metadataJson, err := io.ReadAll(response.Body)
	if err != nil {
		logger.Err(err).Str("protocolVersion", protocolVersion).Msg("couldn't read response body")
		return defaultFallBack
	}

	var metadata LSReleaseMetadata
	err = json.Unmarshal(metadataJson, &metadata)
	if err != nil {
		logger.Err(err).Str("metadata", string(metadataJson)).Str("protocolVersion", protocolVersion).Msg("couldn't unmarshall metadata")
		return defaultFallBack
	}
	exeIfNeeded := ""
	if runtime.GOOS == "windows" {
		exeIfNeeded = ".exe"
	}
	downloadURL := fmt.Sprintf("%s/snyk-ls_%s_%s_%s%s", baseURL, metadata.Version, runtime.GOOS, runtime.GOARCH, exeIfNeeded)

	return downloadURL
}

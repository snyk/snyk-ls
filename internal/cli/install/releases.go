package install

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/snyk-ls/internal/cli/install/httpclient"
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
	baseURL string
}

func NewCLIRelease() *CLIRelease {
	return &CLIRelease{
		baseURL: defaultBaseURL,
	}
}

func (r *CLIRelease) GetLatestRelease(ctx context.Context) (*Release, error) {
	client := httpclient.NewHTTPClient()

	releaseURL := fmt.Sprintf("%s/cli/latest/release.json", r.baseURL)
	logger.
		WithField("method", "GetLatestRelease").
		WithField("url", releaseURL).
		Trace(ctx, "requesting version for Snyk CLI")

	resp, err := client.Get(releaseURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to obtained Snyk CLI release from %q: %s ", releaseURL, resp.Status)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	logger.
		WithField("method", "GetLatestRelease").
		WithField("response_status", resp.Status).
		Trace(ctx, "received")

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

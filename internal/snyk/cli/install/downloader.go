package install

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/snyk/cli/install/httpclient"
)

type Downloader struct{}

func (d *Downloader) Download(r *Release) error {
	if r == nil {
		return fmt.Errorf("release cannot be nil")
	}

	cliDiscovery := Discovery{}

	// download CLI binary
	downloadURL, err := cliDiscovery.DownloadURL(r)
	if err != nil {
		return err
	}
	if downloadURL == "" {
		return fmt.Errorf("no builds found for current OS")
	}

	client := httpclient.NewHTTPClient()

	log.Info().Str("download_url", downloadURL).Msg("downloading Snyk CLI")
	resp, err := client.Get(downloadURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		error_reporting.CaptureError(err)
		return fmt.Errorf("failed to download Snyk CLI from %q: %s", downloadURL, resp.Status)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	var cliReader = resp.Body

	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return err
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tmpDir)

	cliTmpPath := filepath.Join(tmpDir, cliDiscovery.ExecutableName())
	cliFile, err := os.Create(cliTmpPath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(cliFile)

	bytesCopied, err := io.Copy(cliFile, cliReader)
	if err != nil {
		return err
	}
	log.Info().Int64("bytes_copied", bytesCopied).Msgf("copied to %s", cliFile.Name())

	// download checksum
	checksumURL, err := cliDiscovery.ChecksumURL(r)
	if err != nil {
		return err
	}
	if checksumURL == "" {
		return fmt.Errorf("no checksum found for current OS")
	}

	log.Info().Str("checksum_url", checksumURL).Msg("downloading Snyk CLI checksum")
	resp, err = client.Get(checksumURL)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download checksums from %q: %s", checksumURL, resp.Status)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	checksumBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	checksum := string(checksumBytes)

	line := strings.TrimSpace(checksum)
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected checksum line format: %q", line)
	}
	h, err := HashSumFromHexDigest(parts[0])
	if err != nil {
		return err
	}

	err = compareChecksum(h, cliFile.Name())
	if err != nil {
		return err
	}

	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err = os.MkdirAll(lsPath, 0750)
	if err != nil {
		return err
	}
	dstCliFile := filepath.Join(lsPath, cliDiscovery.ExecutableName())
	log.Info().Str("path", dstCliFile).Msg("copying Snyk CLI to user directory")
	err = os.Rename(cliFile.Name(), dstCliFile)
	if err != nil {
		return err
	}

	log.Info().Str("path", dstCliFile).Msg("setting executable bit for Snyk CLI")
	err = cliFile.Chmod(0755)
	if err != nil {
		return err
	}

	return nil
}

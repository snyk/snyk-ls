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
	log.Debug().Str("method", "Download").Interface("release", r).Msg("attempting download")
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

	tmpDirPath := filepath.Join(xdg.DataHome, "snyk-ls", "downloads")
	err = os.MkdirAll(tmpDirPath, 0700)
	if err != nil {
		return err
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tmpDirPath)

	cliTmpPath := filepath.Join(tmpDirPath, cliDiscovery.ExecutableName())
	cliTmpFile, err := os.Create(cliTmpPath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(cliTmpFile)

	bytesCopied, err := io.Copy(cliTmpFile, cliReader)
	if err != nil {
		return err
	}
	log.Info().Int64("bytes_copied", bytesCopied).Msgf("copied to %s", cliTmpFile.Name())

	checksumInfo, err := cliDiscovery.ChecksumInfo(r)
	if err != nil {
		return err
	}
	line := strings.TrimSpace(checksumInfo)
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected checksum line format: %q", line)
	}
	h, err := HashSumFromHexDigest(parts[0])
	if err != nil {
		return err
	}

	err = compareChecksum(h, cliTmpFile.Name())
	if err != nil {
		return err
	}

	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err = os.MkdirAll(lsPath, 0700)
	if err != nil {
		return err
	}
	dstCliFile := filepath.Join(lsPath, cliDiscovery.ExecutableName())
	log.Info().Str("path", dstCliFile).Msg("copying Snyk CLI to user directory")

	// for Windows, we have to remove original file first before move/rename
	if _, err := os.Stat(dstCliFile); err == nil {
		err = os.Remove(dstCliFile)
		if err != nil {
			return err
		}
	}
	err = os.Rename(cliTmpFile.Name(), dstCliFile)
	if err != nil {
		return err
	}

	log.Info().Str("path", dstCliFile).Msg("setting executable bit for Snyk CLI")
	err = cliTmpFile.Chmod(0755)
	if err != nil {
		return err
	}

	return nil
}

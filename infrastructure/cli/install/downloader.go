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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
)

type Downloader struct {
	progressTracker *progress.Tracker
	errorReporter   error_reporting.ErrorReporter
	httpClient      func() *http.Client
}

func NewDownloader(errorReporter error_reporting.ErrorReporter, httpClientFunc func() *http.Client) *Downloader {
	return &Downloader{
		progressTracker: progress.NewTracker(true),
		errorReporter:   errorReporter,
		httpClient:      httpClientFunc,
	}
}

// writeCounter counts the number of bytes written to it.
type writeCounter struct {
	total           int64 // total size
	downloaded      int64 // downloaded # of bytes transferred
	onProgress      func(downloaded int64, total int64, progressTracker *progress.Tracker)
	progressTracker *progress.Tracker
}

// Write implements the io.Writer interface.
//
// Always completes and never returns an error.
func (wc *writeCounter) Write(p []byte) (n int, e error) {
	n = len(p)
	wc.downloaded += int64(n)
	wc.onProgress(wc.downloaded, wc.total, wc.progressTracker)
	return
}

func newWriter(size int64, progressTracker *progress.Tracker, onProgress func(downloaded, total int64, progressTracker *progress.Tracker)) io.Writer {
	return &writeCounter{total: size, progressTracker: progressTracker, onProgress: onProgress}
}

func onProgress(downloaded, total int64, progressTracker *progress.Tracker) {
	percentage := float64(downloaded) / float64(total) * 100
	progressTracker.Report(int(percentage))
}

func (d *Downloader) lockFileName() string {
	return config.CurrentConfig().CLIDownloadLockFileName()
}

func (d *Downloader) Download(r *Release, isUpdate bool) error {
	logger := log.With().Str("method", "Download").Logger()
	if r == nil {
		return fmt.Errorf("release cannot be nil")
	}
	kindStr := "download"
	if isUpdate {
		kindStr = "update"
	}
	logger.Debug().Str("release", r.Version).Msgf("attempting %s", kindStr)

	cliDiscovery := Discovery{}

	// download CLI binary
	downloadURL, err := cliDiscovery.DownloadURL(r)
	if err != nil {
		return err
	}
	if downloadURL == "" {
		return fmt.Errorf("no builds found for current OS")
	}

	logger.Info().Str("download_url", downloadURL).Msgf("Snyk CLI %s in progress...", kindStr)

	if isUpdate {
		d.progressTracker.BeginWithMessage("Updating Snyk CLI...", "")
	} else {
		d.progressTracker.BeginWithMessage("Downloading Snyk CLI...", "We download Snyk CLI to run security scans.")
	}

	doneCh := make(chan bool)

	var resp *http.Response

	resp, err = d.httpClient().Get(downloadURL) //nolint:bodyclose // body is closed in a longer-lived goroutine
	logger.Debug().Any("response-headers", resp.Header).Msg("headers")
	if err != nil {
		return err
	}

	go func(body io.ReadCloser) {
		d.progressTracker.CancelOrDone(func() {
			_ = body.Close()

			logger.Info().Msgf("Cancellation received. Aborting %s.", kindStr)
		}, doneCh)
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		d.errorReporter.CaptureError(err)
		return fmt.Errorf("failed to %s Snyk CLI from %q: %s", kindStr, downloadURL, resp.Status)
	}
	executableFileName := cliDiscovery.ExecutableName(isUpdate)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
		doneCh <- true
		logger.Info().Msgf("finished Snyk CLI %s", kindStr)
	}(resp.Body)

	// pipe stream
	cliReader := io.TeeReader(resp.Body, newWriter(resp.ContentLength, d.progressTracker, onProgress))

	err = os.MkdirAll(xdg.DataHome, 0755)
	if err != nil {
		logger.Err(err).Msg("couldn't create xdg.DataHome directory")
		return err
	}
	tmpDirPath, err := os.MkdirTemp(xdg.DataHome, "downloads")
	if err != nil {
		logger.Err(err).Msg("couldn't create tmpdir")
		return err
	}

	cliTmpPath := filepath.Join(tmpDirPath, executableFileName)
	cliTmpFile, err := os.Create(cliTmpPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = cliTmpFile.Close()
		_ = os.RemoveAll(tmpDirPath)
	}()

	bytesCopied, err := io.Copy(cliTmpFile, cliReader)
	if err != nil {
		return err
	}
	logger.Info().Int64("bytes_copied", bytesCopied).Msgf("copied to %s", cliTmpFile.Name())

	expectedChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return err
	}

	err = compareChecksum(expectedChecksum, cliTmpFile.Name())
	if err != nil {
		return err
	}

	_ = cliTmpFile.Close() // close file to allow moving it on Windows
	err = d.moveToDestination(executableFileName, cliTmpFile.Name())

	if isUpdate {
		d.progressTracker.EndWithMessage("Snyk CLI has been updated.")
	} else {
		d.progressTracker.EndWithMessage("Snyk CLI has been downloaded.")
	}

	return err
}

func (d *Downloader) createLockFile() error {
	lockFile := d.lockFileName()

	file, err := os.Create(lockFile)
	if err != nil {
		log.Err(err).Str("method", "createLockFile").Str("lockfile", lockFile).Msg("couldn't create lockfile")
		return err
	}
	defer func(file *os.File) { _ = file.Close() }(file)
	return nil
}

func (d *Downloader) moveToDestination(destinationFileName string, sourceFilePath string) error {
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", "moveToDestination").Logger()
	cliDirectory := filepath.Dir(c.CliSettings().Path())
	err := os.MkdirAll(cliDirectory, 0755)
	if err != nil {
		msg := fmt.Sprintf("couldn't create directory for Snyk CLI at %s. "+
			"Please change permissions or configured CLI path.", cliDirectory)
		err = errors.Wrap(err, msg)
		logger.Err(err).Send()
		return err
	}
	destinationFilePath := filepath.Join(cliDirectory, destinationFileName) // snyk-win.exe.latest
	logger.Info().Str("path", destinationFilePath).Msg("copying Snyk CLI to user directory")

	// for Windows, we have to remove original file first before move/rename
	if fileInfo, statErr := os.Stat(destinationFilePath); statErr == nil {
		removeErr := os.Remove(destinationFilePath)
		if removeErr != nil {
			returnErr := errors.Wrap(
				removeErr,
				fmt.Sprintf("couldn't remove old CLI at %s. FileInfo: %v", destinationFilePath, fileInfo),
			)
			logger.Err(returnErr).Send()
			return err
		}
	}

	logger.Info().Str("tempFilePath", sourceFilePath).Msg("tempfile path")
	err = os.Rename(sourceFilePath, destinationFilePath)
	if err != nil {
		returnErr :=
			errors.Wrap(
				err,
				fmt.Sprintf("couldn't rename Snyk CLI from %s to %s", sourceFilePath, destinationFilePath),
			)
		logger.Err(returnErr).Send()
		return returnErr
	}

	logger.Info().Str("path", destinationFilePath).Msg("setting executable bit for Snyk CLI")
	err = os.Chmod(destinationFilePath, 0755)
	if err != nil {
		returnErr :=
			errors.Wrap(err, fmt.Sprintf("couldn't set executable bit for Snyk CLI at %s", destinationFilePath))
		logger.Err(returnErr).Send()
		return returnErr
	}
	return nil
}

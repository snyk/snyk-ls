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

	"github.com/pkg/errors"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/types"
)

type Downloader struct {
	progressTask   *progress.Task // per-download task; always set by both constructors
	errorReporter  error_reporting.ErrorReporter
	httpClient     func() *http.Client
	engine         workflow.Engine
	configResolver types.ConfigResolverInterface
}

func NewDownloader(engine workflow.Engine, errorReporter error_reporting.ErrorReporter, httpClientFunc func() *http.Client, configResolver types.ConfigResolverInterface) *Downloader {
	// Create a standalone per-call tracker for the legacy constructor path.
	// This tracker is not shared with any server — it is APPROVED-KEEP as a
	// per-invocation value, not a package-global [IDE-2036].
	standaloneOwner := progress.NewTracker(engine.GetLogger())
	return &Downloader{
		progressTask:   standaloneOwner.New(true),
		errorReporter:  errorReporter,
		httpClient:     httpClientFunc,
		engine:         engine,
		configResolver: configResolver,
	}
}

// NewDownloaderWithOwner creates a Downloader whose progress events are routed
// to the caller-supplied per-server Tracker instead of the global channel.
// This is the preferred constructor for production use [IDE-2036].
func NewDownloaderWithOwner(engine workflow.Engine, errorReporter error_reporting.ErrorReporter, httpClientFunc func() *http.Client, configResolver types.ConfigResolverInterface, owner *progress.Tracker) *Downloader {
	return &Downloader{
		progressTask:   owner.New(true),
		errorReporter:  errorReporter,
		httpClient:     httpClientFunc,
		engine:         engine,
		configResolver: configResolver,
	}
}

// activeProgressBar returns the progress Task for this download.
func (d *Downloader) activeProgressBar() progressReporter {
	return d.progressTask
}

// progressReporter is the subset of ui.ProgressBar used internally by the
// downloader. Using an interface keeps writeCounter/newWriter free of the
// concrete *Tracker/*Task types.
type progressReporter interface {
	BeginWithMessage(title, message string)
	Report(percentage int)
	EndWithMessage(message string)
	CancelOrDone(onCancel func(), doneCh <-chan struct{})
}

// writeCounter counts the number of bytes written to it.
type writeCounter struct {
	total        int64 // total size
	downloaded   int64 // downloaded # of bytes transferred
	onProgressFn func(downloaded int64, total int64, pb progressReporter)
	pb           progressReporter
}

// Write implements the io.Writer interface.
//
// Always completes and never returns an error.
func (wc *writeCounter) Write(p []byte) (n int, e error) {
	n = len(p)
	wc.downloaded += int64(n)
	wc.onProgressFn(wc.downloaded, wc.total, wc.pb)
	return
}

func newWriter(size int64, pb progressReporter, onProgressFn func(downloaded, total int64, pb progressReporter)) io.Writer {
	return &writeCounter{total: size, pb: pb, onProgressFn: onProgressFn}
}

func onProgress(downloaded, total int64, pb progressReporter) {
	percentage := float64(downloaded) / float64(total) * 100
	pb.Report(int(percentage))
}

func (d *Downloader) lockFileName() (string, error) {
	return config.CLIDownloadLockFileName(d.engine.GetConfiguration())
}

func (d *Downloader) validateDownloadPreconditions(r *Release) error {
	if r == nil {
		return fmt.Errorf("release cannot be nil")
	}
	if d.httpClient == nil {
		return fmt.Errorf("http client function is not configured")
	}
	return nil
}

func downloadKind(isUpdate bool) string {
	if isUpdate {
		return "update"
	}
	return "download"
}

func (d *Downloader) Download(r *Release, isUpdate bool) error {
	if err := d.validateDownloadPreconditions(r); err != nil {
		return err
	}
	logger := d.engine.GetLogger().With().Str("method", "Download").Logger()
	kindStr := downloadKind(isUpdate)
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

	logger.Debug().Str("download_url", downloadURL).Msgf("Snyk CLI %s in progress...", kindStr)

	pb := d.activeProgressBar()
	if isUpdate {
		pb.BeginWithMessage("Updating Snyk CLI...", "")
	} else {
		pb.BeginWithMessage("Downloading Snyk CLI...", "We download Snyk CLI to run security scans.")
	}

	doneCh := make(chan struct{}, 1)

	var resp *http.Response

	resp, err = d.httpClient().Get(downloadURL) //nolint:bodyclose // body is closed in a longer-lived goroutine
	if err != nil {
		return err
	}
	logger.Debug().Any("response-headers", resp.Header).Msg("headers")

	go func(body io.ReadCloser) {
		cancel := func() {
			_ = body.Close()
			logger.Debug().Msgf("Cancellation received. Aborting %s.", kindStr)
		}
		pb.CancelOrDone(cancel, doneCh)
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		d.errorReporter.CaptureError(err)
		return fmt.Errorf("failed to %s Snyk CLI from %q: %s", kindStr, downloadURL, resp.Status)
	}
	executableFileName := cliDiscovery.ExecutableName(isUpdate)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
		doneCh <- struct{}{}
		logger.Debug().Msgf("finished Snyk CLI %s", kindStr)
	}(resp.Body)

	// pipe stream
	cliReader := io.TeeReader(resp.Body, newWriter(resp.ContentLength, pb, onProgress))

	cliPath := d.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	cliDirectory := filepath.Dir(cliPath)
	err = os.MkdirAll(cliDirectory, 0755)
	if err != nil {
		logger.Err(err).Msg("couldn't create directory for Snyk CLI")
		return err
	}
	tmpDirPath, err := os.MkdirTemp(cliDirectory, "downloads")
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
	logger.Debug().Int64("bytes_copied", bytesCopied).Msgf("copied to %s", cliTmpFile.Name())

	expectedChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return err
	}

	err = compareChecksum(d.engine.GetLogger(), expectedChecksum, cliTmpFile.Name())
	if err != nil {
		return err
	}

	_ = cliTmpFile.Close() // close file to allow moving it on Windows
	err = d.moveToDestination(executableFileName, cliTmpFile.Name())

	if isUpdate {
		pb.EndWithMessage("Snyk CLI has been updated.")
	} else {
		pb.EndWithMessage("Snyk CLI has been downloaded.")
	}

	return err
}

func (d *Downloader) createLockFile() error {
	lockFile, err := d.lockFileName()
	if err != nil {
		return err
	}

	file, err := os.Create(lockFile)
	if err != nil {
		d.engine.GetLogger().Err(err).Str("method", "createLockFile").Str("lockfile", lockFile).Msg("couldn't create lockfile")
		return err
	}
	defer func(file *os.File) { _ = file.Close() }(file)
	return nil
}

func (d *Downloader) moveToDestination(destinationFileName string, sourceFilePath string) error {
	logger := d.engine.GetLogger().With().Str("method", "moveToDestination").Logger()
	cliPath := d.configResolver.GetString(types.SettingCliPath, nil)
	if cliPath != "" {
		cliPath = filepath.Clean(cliPath)
	}
	cliDirectory := filepath.Dir(cliPath)
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

	logger.Debug().Str("tempFilePath", sourceFilePath).Msg("tempfile path")
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

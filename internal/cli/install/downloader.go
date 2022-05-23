package install

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/install/httpclient"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
)

type Downloader struct {
	progressTracker *progress.Tracker
}

func NewDownloader() *Downloader {
	return &Downloader{progressTracker: progress.NewTracker(true)}
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
	percentage := float64(downloaded) / float64(total) * 100 // todo: don't report every byte
	progressTracker.Report(int(percentage))
	time.Sleep(time.Millisecond * 2)
}

func (d *Downloader) lockFileName() string {
	return config.CurrentConfig().CLIDownloadLockFileName()
}

func (d *Downloader) Download(r *Release, isUpdate bool) error {
	if r == nil {
		return fmt.Errorf("release cannot be nil")
	}
	kindStr := "download"
	if isUpdate {
		kindStr = "update"
	}
	log.Debug().Str("method", "Download").Str("release", r.Version).Msgf("attempting %s", kindStr)

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

	log.Info().Str("download_url", downloadURL).Msgf("Snyk CLI %s in progress...", kindStr)

	if isUpdate {
		d.progressTracker.Begin("Updating Snyk CLI...", "")
	} else {
		d.progressTracker.Begin("Downloading Snyk CLI...", "We download Snyk CLI to run security scans.")
	}

	doneCh := make(chan bool)

	var resp *http.Response

	// Determine the binary size
	length, err := getContentLength(client, downloadURL)
	if err != nil {
		return err
	}

	resp, err = client.Get(downloadURL)
	if err != nil {
		return err
	}

	go func(body io.ReadCloser) {
		d.progressTracker.CancelOrDone(func() {
			_ = body.Close()

			log.Info().Str("method", "Download").Msgf("Cancellation received. Aborting %s.", kindStr)
		}, doneCh)
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		error_reporting.CaptureError(err)
		return fmt.Errorf("failed to %s Snyk CLI from %q: %s", kindStr, downloadURL, resp.Status)
	}
	executablePath := cliDiscovery.ExecutableName(isUpdate)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
		doneCh <- true
		log.Info().Str("method", "Download").Msgf("finished Snyk CLI %s", kindStr)
	}(resp.Body)

	// pipe stream
	cliReader := io.TeeReader(resp.Body, newWriter(int64(length), d.progressTracker, onProgress))

	_ = os.MkdirAll(xdg.DataHome, 0755)
	tmpDirPath, err := os.MkdirTemp(xdg.DataHome, "downloads")
	if err != nil {
		log.Err(err).Str("method", "Download").Msg("couldn't create tmpdir")
		return err
	}

	cliTmpPath := filepath.Join(tmpDirPath, executablePath)
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
	log.Info().Int64("bytes_copied", bytesCopied).Msgf("copied to %s", cliTmpFile.Name())

	expectedChecksum, err := expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return err
	}

	err = compareChecksum(expectedChecksum, cliTmpFile.Name())
	if err != nil {
		return err
	}

	_ = cliTmpFile.Close() // close file to allow moving it on Windows
	err = d.moveToDestination(executablePath, cliTmpFile.Name())

	if isUpdate {
		d.progressTracker.End("Snyk CLI has been updated.")
	} else {
		d.progressTracker.End("Snyk CLI has been downloaded.")
	}

	return err
}

func getContentLength(client *http.Client, downloadURL string) (int, error) {
	resp, err := client.Head(downloadURL)
	if err != nil {
		return 0, err
	}
	contentLength := resp.Header.Get("content-length")
	length, err := strconv.Atoi(contentLength)
	if err != nil {
		return 0, err
	}
	return length, nil
}

func (d *Downloader) createLockFile() error {
	lockFile := d.lockFileName()

	file, err := os.Create(lockFile)
	if err != nil {
		log.Err(err).Str("method", "createLockFile").Str("lockfile", lockFile).Msg("couldn't create lockfile")
		return err
	}
	defer file.Close()
	return nil
}

func (d *Downloader) moveToDestination(dest string, fullSrcPath string) (err error) {
	lsPath := config.CurrentConfig().LsPath()
	dstCliFile := filepath.Join(lsPath, dest)
	log.Info().Str("method", "moveToDestination").Str("path", dstCliFile).Msg("copying Snyk CLI to user directory")

	// for Windows, we have to remove original file first before move/rename
	if _, err := os.Stat(dstCliFile); err == nil {
		err = os.Remove(dstCliFile)
		if err != nil {
			return err
		}
	}
	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()
	log.Info().Str("method", "moveToDestination").Str("tempFilePath", fullSrcPath).Msg("tempfile path")
	err = os.Rename(fullSrcPath, dstCliFile)
	if err != nil {
		return err
	}

	log.Info().Str("method", "moveToDestination").Str("path", dstCliFile).Msg("setting executable bit for Snyk CLI")
	err = os.Chmod(dstCliFile, 0755)
	if err != nil {
		return err
	}
	return nil
}

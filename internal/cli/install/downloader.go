package install

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/install/httpclient"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/lsp"
)

type Downloader struct{}

// writeCounter counts the number of bytes written to it.
type writeCounter struct {
	total         int64 // total size
	downloaded    int64 // downloaded # of bytes transferred
	onProgress    func(downloaded int64, total int64, progressToken lsp.ProgressToken)
	progressToken lsp.ProgressToken
}

// Write implements the io.Writer interface.
//
// Always completes and never returns an error.
func (wc *writeCounter) Write(p []byte) (n int, e error) {
	n = len(p)
	wc.downloaded += int64(n)
	wc.onProgress(wc.downloaded, wc.total, wc.progressToken)
	return
}

func newWriter(size int64, progressToken lsp.ProgressToken, onProgress func(downloaded, total int64, progressToken lsp.ProgressToken)) io.Writer {
	return &writeCounter{total: size, progressToken: progressToken, onProgress: onProgress}
}

func onProgress(downloaded, total int64, progressToken lsp.ProgressToken) {
	percentage := float64(downloaded) / float64(total) * 100
	progress.ReportProgress(progressToken, uint32(percentage), progress.ProgressChannel)
	time.Sleep(time.Millisecond * 3) // todo: remove artificial download delay
}

func (d *Downloader) lockFileName() (string, error) {
	path, err := d.lsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "snyk-cli-download.lock"), nil
}

func (d *Downloader) Download(r *Release) error {
	if r == nil {
		return fmt.Errorf("release cannot be nil")
	}
	log.Debug().Str("method", "Download").Str("release", r.Version).Msg("attempting download")

	lockFileName, err := d.lockFileName()
	if err != nil {
		return err
	}
	fileInfo, err := os.Stat(lockFileName)
	if err == nil && (time.Since(fileInfo.ModTime()) < 1*time.Hour) {
		msg := fmt.Sprintf("lockfile from %v found, not downloading", fileInfo.ModTime())
		log.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg(msg)
		return errors.New(msg)
	}
	err = d.createLockFile()
	if err != nil {
		return err
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			log.Error().Str("method", "Download").Str("lockfile", lockFileName).Msg("couldn't clean up lockfile")
		}
	}(lockFileName)

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
	prog := progress.New("Snyk CLI download", "Downloading Snyk CLI", true)
	progress.BeginProgress(prog, progress.ProgressChannel)
	doneCh := make(chan bool)

	var resp *http.Response

	// Determine the binary size
	length, err := getContentLength(resp, err, client, downloadURL)
	if err != nil {
		return err
	}

	resp, err = client.Get(downloadURL)
	if err != nil {
		return err
	}

	go func(body io.ReadCloser) {
		for {
			select {
			case token := <-progress.CancelProgressChannel:
				if token == prog.Token {
					body.Close()
					log.Info().Str("method", "Download").Msg("Cancellation received. Aborting download.")
				}
			case <-doneCh:
				return
			}
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		error_reporting.CaptureError(err)
		return fmt.Errorf("failed to download Snyk CLI from %q: %s", downloadURL, resp.Status)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
		doneCh <- true
		log.Info().Str("method", "Download").Msg("finished downloading Snyk CLI")
	}(resp.Body)

	time.Sleep(time.Second * 3) // todo: remove artificial download delay
	// pipe stream
	cliReader := io.TeeReader(resp.Body, newWriter(int64(length), prog.Token, onProgress))

	_ = os.MkdirAll(xdg.DataHome, 0755)
	tmpDirPath, err := os.MkdirTemp(xdg.DataHome, "downloads")
	if err != nil {
		log.Err(err).Str("method", "Download").Msg("couldn't create tmpdir")
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

	expectedChecksum, err := d.expectedChecksum(r, &cliDiscovery)
	if err != nil {
		return err
	}

	err = compareChecksum(expectedChecksum, cliTmpFile.Name())
	if err != nil {
		return err
	}

	err = d.moveToDestination(&cliDiscovery, cliTmpFile.Name())

	// successCh <- true
	progress.EndProgress(prog.Token, "Snyk CLI has been downloaded.", progress.ProgressChannel)

	return err
}

func getContentLength(resp *http.Response, err error, client *http.Client, downloadURL string) (int, error) {
	resp, err = client.Head(downloadURL)
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
	lockFile, err := d.lockFileName()
	if err != nil {
		log.Err(err).Str("method", "createLockFile").Str("lockfile", lockFile).Msg("error getting lock file name")
		return err
	}

	file, err := os.Create(lockFile)
	if err != nil {
		log.Err(err).Str("method", "createLockFile").Str("lockfile", lockFile).Msg("couldn't create lockfile")
		return err
	}
	defer file.Close()
	return nil
}

func (d *Downloader) expectedChecksum(r *Release, cliDiscovery *Discovery) (HashSum, error) {
	checksumInfo, err := cliDiscovery.ChecksumInfo(r)
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(checksumInfo)
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected checksum line format: %q", line)
	}
	h, err := HashSumFromHexDigest(parts[0])
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (d *Downloader) moveToDestination(cliDiscovery *Discovery, cliTmpFile string) (err error) {
	lsPath, err := d.lsPath()
	if err != nil {
		return err
	}
	dstCliFile := filepath.Join(lsPath, cliDiscovery.ExecutableName())
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
	log.Info().Str("method", "moveToDestination").Str("tempFilePath", cliTmpFile).Msg("tempfile path")
	err = os.Rename(cliTmpFile, dstCliFile)
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

func (d *Downloader) lsPath() (string, error) {
	lsPath := filepath.Join(xdg.DataHome, "snyk-ls")
	err := os.MkdirAll(lsPath, 0755)
	if err != nil {
		log.Err(err).Str("method", "lsPath").Msgf("couldn't create %s", lsPath)
		return "", err
	}
	return lsPath, nil
}

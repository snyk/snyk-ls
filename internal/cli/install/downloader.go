package install

import (
	"context"
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

func newWriter(size int64, onProgress func(downloaded, total int64, progressToken lsp.ProgressToken)) io.Writer {
	return &writeCounter{total: size, onProgress: onProgress}
}

func onProgress(downloaded, total int64, progressToken lsp.ProgressToken) {
	fmt.Printf("Downloaded %d bytes for a total of %d\n", downloaded, total)
	percentage := float64(downloaded) / float64(total) * 100
	progress.ReportProgress(progressToken, uint32(percentage), progress.ProgressChannel)
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
	pr := progress.New("Snyk CLI download", "Downloading Snyk CLI", true)
	progress.BeginProgress(pr, progress.ProgressChannel)

	cx, _ := context.WithCancel(context.Background()) // todo: use cancel() when message gets received
	req, _ := http.NewRequest("GET", downloadURL, nil)
	req = req.WithContext(cx)
	errorCh := make(chan error)

	var resp *http.Response

	// Determinate the file size
	resp, err = client.Head(downloadURL)
	if err != nil {
		return err
	}
	contentLength := resp.Header.Get("content-length")
	length, err := strconv.Atoi(contentLength)
	if err != nil {
		return err
	}

	go func() {
		resp, err = http.DefaultClient.Do(req)
		select {
		case <-cx.Done():
			// Already timedout
		default:
			errorCh <- err
		}
	}()

	select {
	case err := <-errorCh:
		if err != nil {
			return err // HTTP error
		}
	case <-cx.Done():
		return cx.Err() // todo: verify if that's cancellation issued case?
	}

	if resp.StatusCode != http.StatusOK {
		error_reporting.CaptureError(err)
		return fmt.Errorf("failed to download Snyk CLI from %q: %s", downloadURL, resp.Status)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// pipe stream
	cliReader := io.TeeReader(resp.Body, newWriter(int64(length), onProgress))

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

	progress.EndProgress(pr.Token, "Snyk CLI has been downloaded.", progress.ProgressChannel)

	return err
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

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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/progress"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestDownloader_Download(t *testing.T) {
	testutil.SkipLocally(t)
	engine := testutil.IntegTest(t)
	r := getTestAsset()
	progressCh := make(chan types.ProgressParams, 100000)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return http.DefaultClient },
		engine:          engine,
	}
	exec := (&Discovery{}).ExecutableName(false)
	destination := filepath.Join(t.TempDir(), exec)
	lockFileName, err := d.lockFileName()
	require.NoError(t, err)
	// remove any existing lockfile
	_ = os.RemoveAll(lockFileName)

	_, err = d.Download(r, destination, false)

	assert.NoError(t, err)
	assert.NotEmpty(t, progressCh)
	assert.True(t, len(progressCh) >= 3) // has at least started, reported & finished progress

	//make sure cleanup works
	_, err = os.Stat(lockFileName)
	if err == nil {
		_ = os.RemoveAll(lockFileName)
	}
	assert.Error(t, err)
}

func Test_DoNotDownloadIfCancelled(t *testing.T) {
	engine := testutil.IntegTest(t)
	progressCh := make(chan types.ProgressParams, 100000)
	cancelProgressCh := make(chan bool, 1)
	progressTracker := progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger())
	d := &Downloader{
		progressTracker: progressTracker,
		httpClient:      func() *http.Client { return http.DefaultClient },
		engine:          engine,
	}

	r := getTestAsset()
	cliPath := filepath.Join(t.TempDir(), (&Discovery{}).ExecutableName(false))

	// simulate cancellation when some progress received
	go func() {
		<-progressCh
		progress.Cancel(progressTracker.GetToken())
	}()

	_, err := d.Download(r, cliPath, false)
	require.Error(t, err)

	lockFileName, err := config.CLIDownloadLockFileName(engine.GetConfiguration())
	require.NoError(t, err)

	require.Eventuallyf(t, func() bool {
		_, err := os.Stat(lockFileName)
		return err != nil
	}, time.Second*2, time.Millisecond, "lock file should not exist")
}

func TestDownloaderDownload_ReturnsErrorWhenCliPathIsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	requested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
	}))
	t.Cleanup(server.Close)

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return server.Client() })
	exec := (&Discovery{}).ExecutableName(false)

	got, err := downloader.Download(testRelease(server.URL, "deadbeef  "+exec), "", false)

	require.Error(t, err)
	assert.Empty(t, got)
	assert.False(t, requested, "Download should not hit the network when cliPath is empty")
}

// closeSignalingBody wraps a response body and signals on closed when Close is called,
// so a test can detect whether Download closed the body without blocking forever.
type closeSignalingBody struct {
	io.ReadCloser
	closed chan struct{}
}

func (b *closeSignalingBody) Close() error {
	err := b.ReadCloser.Close()
	select {
	case b.closed <- struct{}{}:
	default:
	}
	return err
}

type closeTrackingTransport struct {
	closed chan struct{}
}

func (rt *closeTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	resp.Body = &closeSignalingBody{ReadCloser: resp.Body, closed: rt.closed}
	return resp, nil
}

func TestDownloaderDownload_ClosesResponseBodyOnNon200Status(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	closed := make(chan struct{}, 1)
	client := &http.Client{Transport: &closeTrackingTransport{closed: closed}}
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return client },
		engine:          engine,
		errorReporter:   error_reporting.NewTestErrorReporter(engine),
	}
	exec := (&Discovery{}).ExecutableName(false)
	cliPath := filepath.Join(t.TempDir(), exec)

	_, err := d.Download(testRelease(server.URL, "deadbeef  "+exec), cliPath, false)

	require.Error(t, err)
	select {
	case <-closed:
		// response body was closed as expected
	case <-time.After(2 * time.Second):
		t.Fatal("expected response body to be closed after a non-200 status, but it leaked")
	}
	assertProgressEndedWithFailure(t, progressCh)
}

// erroringTransport fails every request at the transport level, simulating a
// network failure (e.g. DNS failure, connection refused) from d.httpClient().Get.
type erroringTransport struct{}

func (rt *erroringTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}

func TestDownloaderDownload_ReportsFailureEndWhenHttpGetFails(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	client := &http.Client{Transport: &erroringTransport{}}
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return client },
		engine:          engine,
	}
	cliPath := filepath.Join(t.TempDir(), exec)

	_, err := d.Download(testRelease("http://127.0.0.1:0/asset", "deadbeef  "+exec), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

func TestDownloaderDownload_ReportsFailureEndWhenMkdirAllFails(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	binary := []byte("snyk-cli")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return server.Client() },
		engine:          engine,
	}

	// A regular file where Download needs a directory forces os.MkdirAll to
	// fail with ENOTDIR.
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o644))
	cliPath := filepath.Join(blocker, "sub", exec)

	_, err := d.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", sha256.Sum256(binary), exec)), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

func TestDownloaderDownload_ReportsFailureEndWhenMkdirTempFails(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	binary := []byte("snyk-cli")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return server.Client() },
		engine:          engine,
	}

	// Pre-create the CLI directory without write permission. os.MkdirAll sees
	// the directory already exists and returns nil, but the subsequent
	// os.MkdirTemp inside it needs write permission and fails.
	cliDirectory := filepath.Join(t.TempDir(), "clidir")
	require.NoError(t, os.Mkdir(cliDirectory, 0o555))
	t.Cleanup(func() { _ = os.Chmod(cliDirectory, 0o755) })
	cliPath := filepath.Join(cliDirectory, exec)

	_, err := d.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", sha256.Sum256(binary), exec)), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

// alwaysErrorReader always fails on Read, used to force io.Copy to fail while
// keeping a real, successful HTTP request/response.
type alwaysErrorReader struct{}

func (alwaysErrorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

type bodyReadErrorTransport struct{}

func (rt *bodyReadErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(alwaysErrorReader{})
	return resp, nil
}

func TestDownloaderDownload_ReportsFailureEndWhenIOCopyFails(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	binary := []byte("snyk-cli")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	client := &http.Client{Transport: &bodyReadErrorTransport{}}
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return client },
		engine:          engine,
	}
	cliPath := filepath.Join(t.TempDir(), exec)

	_, err := d.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", sha256.Sum256(binary), exec)), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

func TestDownloaderDownload_ReportsFailureEndWhenChecksumInfoIsMalformed(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	binary := []byte("snyk-cli")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return server.Client() },
		engine:          engine,
	}
	cliPath := filepath.Join(t.TempDir(), exec)

	// A checksum line with only one field fails expectedChecksum's format check.
	_, err := d.Download(testRelease(server.URL, "onlyonefield"), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

func TestDownloaderDownload_ReportsFailureEndWhenChecksumMismatch(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())
	binary := []byte("snyk-cli")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return server.Client() },
		engine:          engine,
	}
	cliPath := filepath.Join(t.TempDir(), exec)

	// Well-formed checksum line, but it does not match the downloaded bytes.
	wrongChecksum := sha256.Sum256([]byte("not-the-downloaded-bytes"))
	_, err := d.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", wrongChecksum, exec)), cliPath, false)

	require.Error(t, err)
	assertProgressEndedWithFailure(t, progressCh)
}

// assertProgressEndedWithFailure drains progressCh (closing it first) and
// asserts a WorkDoneProgressEnd event was sent carrying a failure message, not
// a success one — i.e. the client's progress indicator was not left stuck.
func assertProgressEndedWithFailure(t *testing.T, progressCh chan types.ProgressParams) {
	t.Helper()
	close(progressCh)
	sawEnd := false
	for p := range progressCh {
		end, ok := p.Value.(types.WorkDoneProgressEnd)
		if !ok {
			continue
		}
		sawEnd = true
		assert.NotContains(t, end.Message, "has been downloaded")
		assert.NotContains(t, end.Message, "has been updated")
	}
	assert.True(t, sawEnd, "expected a WorkDoneProgressEnd event, so the client's progress indicator is not left stuck")
}

func TestDownloaderDownload_DoesNotReportSuccessWhenMoveToDestinationFails(t *testing.T) {
	engine := testutil.UnitTest(t)
	t.Chdir(t.TempDir())

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	exec := (&Discovery{}).ExecutableName(false)
	progressCh := make(chan types.ProgressParams, 100)
	cancelProgressCh := make(chan bool, 1)
	d := &Downloader{
		progressTracker: progress.NewTestTracker(progressCh, cancelProgressCh, engine.GetLogger()),
		httpClient:      func() *http.Client { return server.Client() },
		engine:          engine,
		removeFile:      os.Remove,
		renameFile: func(string, string) error {
			return errors.New("simulated rename failure")
		},
	}
	cliPath := filepath.Join(t.TempDir(), exec)

	_, err := d.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, exec)), cliPath, false)

	require.Error(t, err)
	close(progressCh)
	sawEnd := false
	for p := range progressCh {
		end, ok := p.Value.(types.WorkDoneProgressEnd)
		if !ok {
			continue
		}
		sawEnd = true
		assert.NotContains(t, end.Message, "has been downloaded")
		assert.NotContains(t, end.Message, "has been updated")
	}
	assert.True(t, sawEnd, "expected a WorkDoneProgressEnd event even when moveToDestination fails, so the client's progress indicator is not left stuck")
}

func getTestAsset() *Release {
	r := &Release{
		Assets: &ReleaseAssets{
			MacOS: &ReleaseAsset{
				URL:          "https://downloads.snyk.io/cli/v1.1276.0/snyk-macos",
				ChecksumInfo: "00c7f96ce389cff3f79e920ba345efef2ab78f80ffebd8922082dfca07ed3af0  snyk-macos",
			},
			MacOSARM64: &ReleaseAsset{
				URL:          "https://downloads.snyk.io/cli/v1.1276.0/snyk-macos-arm64",
				ChecksumInfo: "691b455a8fdcfb31089ca460658d060b51c58b2e37dc757e8b5434ca0a9b80cf  snyk-macos-arm64",
			},
			Linux: &ReleaseAsset{
				URL:          "https://downloads.snyk.io/cli/v1.1276.0/snyk-linux",
				ChecksumInfo: "4ade26062f3631bf04ca6a75a7c560752585d2aed025a6a4be97517dbb4701ce  snyk-linux",
			},
			LinuxARM64: &ReleaseAsset{
				URL:          "https://downloads.snyk.io/cli/v1.1276.0/snyk-linux-arm64",
				ChecksumInfo: "c26cc7e49354c24d4eeaec41445c612f3b93ad782482fbf9f7d38947815f01a8  snyk-linux-arm64",
			},
			Windows: &ReleaseAsset{
				URL:          "https://downloads.snyk.io/cli/v1.1276.0/snyk-win.exe",
				ChecksumInfo: "76f38b24fe996dcdcb6750f005f2f07044c7a01b7f355d59f88104611a2c9d65  snyk-win.exe",
			},
		},
	}
	return r
}

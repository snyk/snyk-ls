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
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli/filename"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/types/mock_types"
)

func TestInstaller_Find(t *testing.T) {
	engine := testutil.IntegTest(t)

	// prepare temp directory with OS specific dummy CLI binary
	d := &Discovery{}
	cliDir := t.TempDir()
	cliFilePath := filepath.Join(cliDir, d.ExecutableName(false))
	f, _ := os.Create(cliFilePath)
	defer func(f *os.File) { _ = f.Close() }(f)
	_, _ = f.WriteString("dummy-cli-file")
	_ = f.Chmod(0777)

	t.Setenv("PATH", cliDir)

	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.DefaultConfigResolver(engine), testutil.NewDrainedProgressTracker())

	execPath, err := i.Find()

	assert.NoError(t, err)
	assert.NotEmpty(t, execPath)
}

func Test_Find_CliPathInSettings_CliPathFound(t *testing.T) {
	engine := testutil.IntegTest(t)
	// Arrange
	file, err := os.CreateTemp(t.TempDir(), "snyk-win.exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err = file.Close()
		if err != nil {
			t.Logf("Error when trying to close the file in \"%s\":\n%v", file.Name(), err)
		}
	})

	cliPath := file.Name()
	t.Setenv("PATH", "")
	t.Setenv("SNYK_TOKEN", "")
	t.Setenv("SNYK_CLI_PATH", "")
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	installer := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.DefaultConfigResolver(engine), testutil.NewDrainedProgressTracker())

	// Act
	foundPath, err := installer.Find()
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, cliPath, foundPath)
}

func TestDefaultConfigResolver_ResolvesCliPathFromMinimalEngine(t *testing.T) {
	engine, err := testutil.NewMinimalEngine()
	require.NoError(t, err)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)

	assert.Equal(t, cliPath, testutil.DefaultConfigResolver(engine).GetString(types.SettingCliPath, nil))
}

func TestInstallRelease_ReturnsErrorWhenCliPathIsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := mock_types.NewMockConfigResolverInterface(gomock.NewController(t))
	resolver.EXPECT().GetString(types.SettingCliPath, nil).AnyTimes().Return("")
	t.Chdir(t.TempDir())

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		resolver,
		testutil.NewDrainedProgressTracker(),
	)

	got, err := installer.installRelease(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)))

	require.Error(t, err)
	assert.Empty(t, got)
	assert.NoFileExists(t, filename.ExecutableName)
}

func TestUpdateFromRelease_ReturnsErrorWhenCliPathIsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	resolver := mock_types.NewMockConfigResolverInterface(gomock.NewController(t))
	resolver.EXPECT().GetString(types.SettingCliPath, nil).AnyTimes().Return("")
	t.Chdir(t.TempDir())

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		resolver,
		testutil.NewDrainedProgressTracker(),
	)

	updated, err := installer.updateFromRelease(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)))

	require.Error(t, err)
	assert.False(t, updated)
}

func TestInstallRelease_ReturnsInstalledPath_WhenResolverCannotRediscoverIt(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	resolver := mock_types.NewMockConfigResolverInterface(gomock.NewController(t))
	reads := 0
	resolver.EXPECT().GetString(types.SettingCliPath, nil).AnyTimes().DoAndReturn(func(string, *types.FolderConfig) string {
		reads++
		if reads == 1 {
			return cliPath
		}
		return ""
	})
	t.Setenv("PATH", t.TempDir())
	t.Chdir(t.TempDir())

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		resolver,
		testutil.NewDrainedProgressTracker(),
	)

	release := testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName))
	got, err := installer.installRelease(release)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
	assert.Equal(t, 1, reads)
}

func TestInstallerUpdate_ResolvesCliPathOnce(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	require.NoError(t, os.WriteFile(cliPath, []byte("outdated-cli"), 0755))
	resolver := mock_types.NewMockConfigResolverInterface(gomock.NewController(t))
	resolver.EXPECT().GetString(types.SettingCliPath, nil).Times(1).Return(cliPath)
	t.Chdir(t.TempDir())

	binary := []byte("latest-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		resolver,
		testutil.NewDrainedProgressTracker(),
	)

	updated, err := installer.updateFromRelease(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)))

	require.NoError(t, err)
	assert.True(t, updated)
	installedBinary, readErr := os.ReadFile(cliPath)
	require.NoError(t, readErr)
	assert.Equal(t, binary, installedBinary)
}

func TestInstallRelease_ReturnsConfiguredDestination_OnSuccessfulInstall(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	t.Setenv("PATH", t.TempDir())

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		testutil.DefaultConfigResolver(engine),
		testutil.NewDrainedProgressTracker(),
	)

	release := testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName))
	got, err := installer.installRelease(release)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
}

func testRelease(url, checksumInfo string) *Release {
	asset := &ReleaseAsset{URL: url, ChecksumInfo: checksumInfo}
	return &Release{Assets: &ReleaseAssets{
		AlpineLinux: asset,
		Linux:       asset,
		LinuxARM64:  asset,
		MacOS:       asset,
		MacOSARM64:  asset,
		Windows:     asset,
	}}
}

func TestDownloaderDestinationPath_ReturnsConfiguredPath(t *testing.T) {
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	downloader := &Downloader{}
	destinationFileName := "snyk-linux-arm64.latest"

	assert.Equal(t, filepath.Join(filepath.Dir(cliPath), destinationFileName), downloader.destinationPath(cliPath, destinationFileName))
}

func TestDownloaderMoveToDestination_ReturnsErrorWhenCliPathIsEmpty(t *testing.T) {
	engine := testutil.UnitTest(t)
	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.NewDrainedProgressTracker())
	t.Chdir(t.TempDir())

	sourceFile, err := os.CreateTemp(t.TempDir(), "cli-source")
	require.NoError(t, err)
	_, err = sourceFile.WriteString("snyk-cli")
	require.NoError(t, err)
	require.NoError(t, sourceFile.Close())

	got, err := downloader.moveToDestination("", filename.ExecutableName, sourceFile.Name(), nil)

	require.Error(t, err)
	assert.Empty(t, got)
	assert.NoFileExists(t, filename.ExecutableName)
}

func TestDownloaderMoveToDestination_ReturnsExistingPathWhenConcurrentInstallAlreadyWroteExpectedBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	existingBinary := []byte("expected-cli")
	require.NoError(t, os.WriteFile(cliPath, existingBinary, 0755))

	sourceFile, err := os.CreateTemp(t.TempDir(), "cli-source")
	require.NoError(t, err)
	_, err = sourceFile.Write([]byte("new-cli"))
	require.NoError(t, err)
	require.NoError(t, sourceFile.Close())

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.NewDrainedProgressTracker())
	downloader.removeFile = func(string) error { return os.ErrPermission }
	expectedChecksum := sha256.Sum256(existingBinary)

	got, err := downloader.moveToDestination(cliPath, filename.ExecutableName, sourceFile.Name(), expectedChecksum[:])

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
	assert.Equal(t, existingBinary, readFile(t, got))
}

func TestDownloaderMoveToDestination_ReturnsExistingPathWhenConcurrentInstallRenamedExpectedBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	existingBinary := []byte("expected-cli")

	sourceFile, err := os.CreateTemp(t.TempDir(), "cli-source")
	require.NoError(t, err)
	_, err = sourceFile.Write([]byte("new-cli"))
	require.NoError(t, err)
	require.NoError(t, sourceFile.Close())

	renameErr := os.ErrPermission
	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.NewDrainedProgressTracker())
	downloader.renameFile = func(_, destinationFilePath string) error {
		require.NoError(t, os.WriteFile(destinationFilePath, existingBinary, 0755))
		return renameErr
	}
	expectedChecksum := sha256.Sum256(existingBinary)

	got, err := downloader.moveToDestination(cliPath, filename.ExecutableName, sourceFile.Name(), expectedChecksum[:])

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.Equal(t, existingBinary, readFile(t, got))
}

func TestDownloaderMoveToDestination_ReturnsErrorWhenConcurrentInstallRenamedWrongBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)

	sourceFile, err := os.CreateTemp(t.TempDir(), "cli-source")
	require.NoError(t, err)
	_, err = sourceFile.Write([]byte("new-cli"))
	require.NoError(t, err)
	require.NoError(t, sourceFile.Close())

	renameErr := os.ErrPermission
	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.NewDrainedProgressTracker())
	downloader.renameFile = func(_, destinationFilePath string) error {
		require.NoError(t, os.WriteFile(destinationFilePath, []byte("wrong-cli"), 0755))
		return renameErr
	}
	expectedChecksum := sha256.Sum256([]byte("expected-cli"))

	got, err := downloader.moveToDestination(cliPath, filename.ExecutableName, sourceFile.Name(), expectedChecksum[:])

	require.Error(t, err)
	assert.Empty(t, got)
	assert.ErrorIs(t, err, renameErr)
}

func TestDownloaderMoveToDestination_ReturnsErrorWhenExistingBinaryCannotBeRemoved(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	require.NoError(t, os.WriteFile(cliPath, []byte("outdated-cli"), 0755))

	sourceFile, err := os.CreateTemp(t.TempDir(), "cli-source")
	require.NoError(t, err)
	_, err = sourceFile.Write([]byte("new-cli"))
	require.NoError(t, err)
	require.NoError(t, sourceFile.Close())

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.NewDrainedProgressTracker())
	downloader.removeFile = func(string) error { return os.ErrPermission }
	expectedChecksum := sha256.Sum256([]byte("new-cli"))

	got, err := downloader.moveToDestination(cliPath, filename.ExecutableName, sourceFile.Name(), expectedChecksum[:])

	require.Error(t, err)
	assert.Empty(t, got)
	assert.ErrorIs(t, err, os.ErrPermission)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return contents
}

func TestDownloaderDownload_ReturnsExistingPathWhenConcurrentInstallRenamedExpectedBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	existingBinary := []byte("expected-cli")
	checksum := sha256.Sum256(existingBinary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(existingBinary)
	}))
	t.Cleanup(server.Close)

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return server.Client() }, testutil.NewDrainedProgressTracker())
	downloader.renameFile = func(_, destinationFilePath string) error {
		require.NoError(t, os.WriteFile(destinationFilePath, existingBinary, 0755))
		return os.ErrPermission
	}

	got, err := downloader.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)), cliPath, false)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.Equal(t, existingBinary, readFile(t, got))
}

func TestDownloaderDownload_ReturnsExistingPathWhenConcurrentInstallAlreadyWroteExpectedBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	existingBinary := []byte("expected-cli")
	require.NoError(t, os.WriteFile(cliPath, existingBinary, 0755))

	checksum := sha256.Sum256(existingBinary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(existingBinary)
	}))
	t.Cleanup(server.Close)

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return server.Client() }, testutil.NewDrainedProgressTracker())
	downloader.removeFile = func(string) error { return os.ErrPermission }

	got, err := downloader.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)), cliPath, false)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.Equal(t, existingBinary, readFile(t, got))
}

func TestDownloaderDownload_ReturnsErrorWhenConcurrentInstallWroteWrongBinary(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	require.NoError(t, os.WriteFile(cliPath, []byte("outdated-cli"), 0755))

	newBinary := []byte("expected-cli")
	checksum := sha256.Sum256(newBinary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(newBinary)
	}))
	t.Cleanup(server.Close)

	downloader := NewDownloader(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return server.Client() }, testutil.NewDrainedProgressTracker())
	downloader.removeFile = func(string) error { return os.ErrPermission }

	got, err := downloader.Download(testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName)), cliPath, false)

	require.Error(t, err)
	assert.Empty(t, got)
	assert.ErrorIs(t, err, os.ErrPermission)
}

func TestFakeInstaller_Install_ReturnsPath(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	installer := NewFakeInstaller(engine, testutil.DefaultConfigResolver(engine))

	got, err := installer.Install(t.Context())

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
}

// TestInstaller_Install_WaitsForLockThenSucceeds_WhenSiblingLockClearsDuringWait
// reproduces the flaky-CI defect (IDE-2446): a fresh, recently-created lock file
// (simulating a sibling process's in-progress CLI download into a shared
// SNYK_LS_CLI_CACHE_DIR) must not make installRelease hard-fail immediately.
// Instead it should wait for the lock to clear - here the sibling "finishes" and
// removes the lock shortly after our wait starts - and then proceed normally.
func TestInstaller_Install_WaitsForLockThenSucceeds_WhenSiblingLockClearsDuringWait(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	// CLIDownloadLockFileName derives the lock path from the configured CLI path, so
	// the config must be set before computing it - otherwise the test would create the
	// lock file at a different path than installRelease checks.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)

	lockFileName, err := config.CLIDownloadLockFileName(engine.GetConfiguration())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(lockFileName, nil, 0o644))

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		testutil.DefaultConfigResolver(engine),
		testutil.NewDrainedProgressTracker(),
	)
	installer.lockFileTTL = 2 * time.Second
	installer.lockPollInterval = 10 * time.Millisecond

	// Simulate the sibling process finishing its own download and cleaning up its
	// lock file well within our TTL wait bound.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.Remove(lockFileName)
	}()

	release := testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName))
	got, err := installer.installRelease(release)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
}

// TestInstaller_Install_ProceedsOnceLockAgesPastTTL covers a lock file that is
// never cleaned up (e.g. left behind by a crashed sibling process): installRelease
// must still eventually proceed, treating the lock as stale once its age reaches
// the TTL, rather than blocking or failing forever. The TTL/poll interval are
// overridden to keep this bounded in a unit test.
func TestInstaller_Install_ProceedsOnceLockAgesPastTTL(t *testing.T) {
	engine := testutil.UnitTest(t)
	cliPath := filepath.Join(t.TempDir(), filename.ExecutableName)
	// CLIDownloadLockFileName derives the lock path from the configured CLI path, so
	// the config must be set before computing it - otherwise the test would create the
	// lock file at a different path than installRelease checks.
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)

	lockFileName, err := config.CLIDownloadLockFileName(engine.GetConfiguration())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(lockFileName, nil, 0o644))

	binary := []byte("snyk-cli")
	checksum := sha256.Sum256(binary)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(server.Close)

	installer := NewInstaller(
		engine,
		error_reporting.NewTestErrorReporter(engine),
		func() *http.Client { return server.Client() },
		testutil.DefaultConfigResolver(engine),
		testutil.NewDrainedProgressTracker(),
	)
	installer.lockFileTTL = 50 * time.Millisecond
	installer.lockPollInterval = 5 * time.Millisecond
	// lock file is deliberately never removed here.

	release := testRelease(server.URL, fmt.Sprintf("%x  %s", checksum, filename.ExecutableName))
	got, err := installer.installRelease(release)

	require.NoError(t, err)
	assert.Equal(t, cliPath, got)
	assert.FileExists(t, got)
}

func TestInstaller_Update_DoesntUpdateIfNoLatestRelease(t *testing.T) {
	engine := testutil.UnitTest(t)
	// prepare
	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil, testutil.DefaultConfigResolver(engine), testutil.NewDrainedProgressTracker())

	temp := t.TempDir()
	fakeCliFile := testsupport.CreateTempFile(t, temp)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), fakeCliFile.Name())

	checksum, err := getChecksum(engine.GetLogger(), fakeCliFile.Name())
	if err != nil {
		t.Fatal(err, "Error calculating temp file checksum")
	}
	checksumString := hex.EncodeToString(checksum)

	r := &Release{
		Assets: &ReleaseAssets{
			AlpineLinux: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-alpine",
			},
			Linux: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-linux",
			},
			LinuxARM64: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-linux-arm64",
			},
			MacOS: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-macos",
			},
			MacOSARM64: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-macos-arm64",
			},
			Windows: &ReleaseAsset{
				ChecksumInfo: checksumString + "  snyk-win.exe",
			},
		},
	}

	// act
	updated, _ := i.updateFromRelease(r)

	// assert
	assert.False(t, updated)
}

func TestInstaller_Update_DownloadsLatestCli(t *testing.T) {
	testutil.SkipLocally(t)
	engine := testutil.IntegTest(t)

	// prepare
	ctx := t.Context()
	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return http.DefaultClient }, testutil.DefaultConfigResolver(engine), testutil.NewDrainedProgressTracker())
	cliDir := t.TempDir()

	fakeCliFile := testsupport.CreateTempFile(t, cliDir)
	_ = fakeCliFile.Close()
	cliDiscovery := Discovery{}
	cliFilePath := path.Join(cliDir, cliDiscovery.ExecutableName(false))
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingCliPath), cliFilePath)

	err := os.Rename(fakeCliFile.Name(), cliFilePath) // rename temp file to CLI file
	if err != nil {
		t.Fatal(err, "Error renaming temp file")
	}
	defer func(f string) { _ = os.Remove(f) }(cliFilePath)

	r := NewCLIRelease(engine, i.httpClient)
	release, err := r.GetLatestRelease()
	if err != nil {
		t.Fatal(err, "Error getting latest release info")
	}
	expectedChecksum, err := expectedChecksum(release, &cliDiscovery)
	if err != nil {
		t.Fatal(err, "Error calculating expected checksum")
	}

	// act
	updated, err := i.Update(ctx)

	// assert
	assert.True(t, updated)
	assert.NoError(t, err)
	assert.FileExists(t, cliFilePath)
	assert.Nil(t, compareChecksum(engine.GetLogger(), expectedChecksum, cliFilePath))
}

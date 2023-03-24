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
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestInstaller_Find(t *testing.T) {
	testutil.IntegTest(t)

	// prepare temp directory with OS specific dummy CLI binary
	d := &Discovery{}
	cliDir := t.TempDir()
	cliFilePath := filepath.Join(cliDir, d.ExecutableName(false))
	f, _ := os.Create(cliFilePath)
	defer func(f *os.File) { _ = f.Close() }(f)
	_, _ = f.WriteString("dummy-cli-file")
	_ = f.Chmod(0777)

	t.Setenv("PATH", cliDir)

	i := NewInstaller(error_reporting.NewTestErrorReporter(), nil)

	execPath, err := i.Find()

	assert.NoError(t, err)
	assert.NotEmpty(t, execPath)
}

func Test_Find_CliPathInSettings_CliPathFound(t *testing.T) {
	// Arrange
	testutil.IntegTest(t)
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
	config.CurrentConfig().CliSettings().SetPath(cliPath)
	installer := NewInstaller(error_reporting.NewTestErrorReporter(), nil)

	// Act
	foundPath, err := installer.Find()
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, cliPath, foundPath)
}

func TestInstaller_Find_emptyPath(t *testing.T) {
	testutil.IntegTest(t)
	t.Skipf("removes real binaries from user directory")

	t.Setenv("PATH", "")
	i := NewInstaller(error_reporting.NewTestErrorReporter(), nil)

	execPath, err := i.Find()

	assert.Error(t, err)
	assert.Empty(t, execPath)
}

func TestInstaller_Install_DoNotDownloadIfLockfileFound(t *testing.T) {
	r := getTestAsset()

	lockFileName := config.CurrentConfig().CLIDownloadLockFileName()
	file, err := os.Create(lockFileName)
	if err != nil {
		t.Fatal("couldn't create lockfile")
	}
	_ = file.Close()

	i := NewInstaller(error_reporting.NewTestErrorReporter(), nil)
	_, err = i.installRelease(r)

	assert.Error(t, err)
}

func TestInstaller_Update_DoesntUpdateIfNoLatestRelease(t *testing.T) {
	testutil.UnitTest(t)
	// prepare
	i := NewInstaller(error_reporting.NewTestErrorReporter(), nil)

	temp := t.TempDir()
	fakeCliFile := testutil.CreateTempFile(temp, t)
	config.CurrentConfig().CliSettings().SetPath(fakeCliFile.Name())

	checksum, err := getChecksum(fakeCliFile.Name())
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
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)

	// prepare
	ctx := context.Background()
	i := NewInstaller(error_reporting.NewTestErrorReporter(), func() *http.Client { return http.DefaultClient })
	cliDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(t, err, "Failed to create temp dir")
	}
	defer func() { _ = os.Remove(cliDir) }()

	fakeCliFile := testutil.CreateTempFile(cliDir, t)
	_ = fakeCliFile.Close()
	cliDiscovery := Discovery{}
	cliFilePath := path.Join(cliDir, cliDiscovery.ExecutableName(false))
	config.CurrentConfig().CliSettings().SetPath(cliFilePath)

	err = os.Rename(fakeCliFile.Name(), cliFilePath) // rename temp file to CLI file
	if err != nil {
		t.Fatal(err, "Error renaming temp file")
	}
	defer func(f string) { _ = os.Remove(f) }(cliFilePath)

	r := NewCLIRelease(i.httpClient)
	release, err := r.GetLatestRelease(ctx)
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
	assert.Nil(t, compareChecksum(expectedChecksum, cliFilePath))
}

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
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/testsupport"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
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

	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil)

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
	installer := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil)

	// Act
	foundPath, err := installer.Find()
	if err != nil {
		t.Fatal(err)
	}

	// Assert
	assert.Equal(t, cliPath, foundPath)
}

func TestInstaller_Install_DoNotDownloadIfLockfileFound(t *testing.T) {
	engine := testutil.UnitTest(t)
	r := getTestAsset()

	lockFileName, err := config.CLIDownloadLockFileName(engine.GetConfiguration())
	require.NoError(t, err)
	file, err := os.Create(lockFileName)
	if err != nil {
		t.Fatal("couldn't create lockfile")
	}
	_ = file.Close()

	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil)
	_, err = i.installRelease(r)

	assert.Error(t, err)
}

func TestInstaller_Update_DoesntUpdateIfNoLatestRelease(t *testing.T) {
	engine := testutil.UnitTest(t)
	// prepare
	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), nil)

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
	testutil.CreateDummyProgressListener(t)

	// prepare
	ctx := t.Context()
	i := NewInstaller(engine, error_reporting.NewTestErrorReporter(engine), func() *http.Client { return http.DefaultClient })
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

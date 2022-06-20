package install

import (
	"context"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestInstaller_Find(t *testing.T) {
	testutil.IntegTest(t)

	// prepare temp directory with OS specific dummy CLI binary
	d := &Discovery{}
	cliDir := t.TempDir()
	cliFilePath := filepath.Join(cliDir, d.ExecutableName(false))
	f, _ := os.Create(cliFilePath)
	defer func(f *os.File) {
		_ = f.Close()
	}(f)
	_, _ = f.WriteString("dummy-cli-file")
	_ = f.Chmod(0777)

	t.Setenv("PATH", cliDir)

	i := NewInstaller()

	execPath, err := i.Find()

	assert.NoError(t, err)
	assert.NotEmpty(t, execPath)
}

func TestInstaller_Find_emptyPath(t *testing.T) {
	testutil.IntegTest(t)
	t.Skipf("removes real binaries from user directory")

	t.Setenv("PATH", "")
	i := NewInstaller()

	execPath, err := i.Find()

	assert.Error(t, err)
	assert.Empty(t, execPath)
}

func TestInstaller_Install_DoNotDownloadIfLockfileFound(t *testing.T) {
	Mutex.Lock()
	defer Mutex.Unlock()
	r := getTestAsset()

	lockFileName := config.CurrentConfig().CLIDownloadLockFileName()
	file, err := os.Create(lockFileName)
	if err != nil {
		t.Fatal("couldn't create lockfile")
	}
	file.Close()

	i := NewInstaller()
	_, err = i.installRelease(r, context.Background())

	assert.Error(t, err)
}

func TestInstaller_Update_DoesntUpdateIfNoLatestRelease(t *testing.T) {
	testutil.UnitTest(t)
	// prepare
	i := NewInstaller()

	temp := t.TempDir()
	fakeCliFile := testutil.CreateTempFile(temp, t)
	err := config.CurrentConfig().SetCliPath(fakeCliFile.Name())
	if err != nil {
		t.Fatal(t, err, "Error setting CLI path")
	}
	defer func() {
		_ = config.CurrentConfig().SetCliPath("")
	}()

	checksum, err := getChecksum(fakeCliFile.Name())
	if err != nil {
		t.Fatal(t, err, "Error calculating temp file checksum")
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
	i := NewInstaller()

	lsPath := config.CurrentConfig().LsPath()

	fakeCliFile := testutil.CreateTempFile(lsPath, t)
	fakeCliFile.Close()
	cliDiscovery := Discovery{}
	cliFilePath := path.Join(lsPath, cliDiscovery.ExecutableName(false))
	err := os.Rename(fakeCliFile.Name(), cliFilePath) // rename temp file to CLI file
	if err != nil {
		t.Fatal(t, err, "Error renaming temp file")
	}
	defer func(f string) {
		_ = os.Remove(f)
	}(cliFilePath)

	err = config.CurrentConfig().SetCliPath(cliFilePath)
	if err != nil {
		t.Fatal(t, err, "Error setting CLI path")
	}
	defer func() {
		_ = config.CurrentConfig().SetCliPath("")
	}()

	r := NewCLIRelease()
	release, err := r.GetLatestRelease(ctx)
	if err != nil {
		t.Fatal(t, err, "Error getting latest release info")
	}
	expectedChecksum, err := expectedChecksum(release, &cliDiscovery)
	if err != nil {
		t.Fatal(t, err, "Error calculating expected checksum")
	}

	// act
	updated, err := i.Update(ctx)

	// assert
	assert.True(t, updated)
	assert.NoError(t, err)
	assert.FileExists(t, cliFilePath)
	assert.Nil(t, compareChecksum(expectedChecksum, cliFilePath))
}

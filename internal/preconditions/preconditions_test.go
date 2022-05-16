package preconditions

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_EnsureCliShouldFindOrDownloadCliAndAddPathToEnv(t *testing.T) {
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)

	_ = config.CurrentConfig.SetCliPath("")
	if !config.CurrentConfig.Authenticated() {
		_ = config.CurrentConfig.SetToken("dummy") // we don't want to authenticate
	}
	EnsureReadyForAnalysisAndWait()
	assert.NotEmpty(t, config.CurrentConfig.CliPath())
}

func Test_EnsureCLIShouldRespectCliPathInEnv(t *testing.T) {
	testutil.UnitTest(t)
	tempDir := t.TempDir()
	tempFile := testutil.CreateTempFile(tempDir, t)
	err := config.CurrentConfig.SetCliPath(tempFile.Name())
	if err != nil {
		t.Fatal(t, "Couldn't set cli path in config.CurrentConfig")
	}
	defer func() {
		_ = config.CurrentConfig.SetCliPath("")
	}()

	EnsureReadyForAnalysisAndWait()

	assert.Equal(t, tempFile.Name(), config.CurrentConfig.CliPath())
}

func Test_isOutdatedCli_DetectsOutdatedCli(t *testing.T) {
	// prepare user directory with OS specific dummy CLI binary
	temp := t.TempDir()
	file := testutil.CreateTempFile(temp, t)

	err := config.CurrentConfig.SetCliPath(file.Name())
	if err != nil {
		t.Fatal(t, "Failed to set cli path to the temp cli file")
	}

	outdatedTime := time.Now().Add(-time.Hour*24*4 - time.Second*1)
	err = os.Chtimes(file.Name(), outdatedTime, outdatedTime)
	if err != nil {
		t.Fatal(t, "Failed to set the access and modification times of the temp cli file")
	}

	// act
	isOutdated := isOutdatedCli()

	// assert
	assert.True(t, isOutdated)
}

func Test_isOutdatedCli_DetectsLatestCli(t *testing.T) {
	// prepare user directory with OS specific dummy CLI binary
	temp := t.TempDir()
	file := testutil.CreateTempFile(temp, t)
	err := config.CurrentConfig.SetCliPath(file.Name())
	if err != nil {
		t.Fatal(t, "Failed to set cli path to the temp cli file")
	}
	defer func() {
		_ = config.CurrentConfig.SetCliPath("")
	}()

	latestTime := time.Now().Add(time.Hour * 24 * 4) // exactly 4 days is considered as not outdated.
	err = os.Chtimes(file.Name(), latestTime, latestTime)
	if err != nil {
		t.Fatal(t, "Failed to set the access and modification times of the temp cli file")
	}

	// act
	isOutdated := isOutdatedCli()

	// assert
	assert.False(t, isOutdated)
}

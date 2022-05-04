package preconditions

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_EnsureCliShouldFindOrDownloadCliAndAddPathToEnv(t *testing.T) {
	testutil.IntegTest(t)
	testutil.CreateDummyProgressListener(t)

	_ = environment.SetCliPath("")
	if !environment.Authenticated() {
		_ = environment.SetToken("dummy") // we don't want to authenticate
	}
	EnsureReadyForAnalysisAndWait()
	assert.NotEmpty(t, environment.CliPath())
}

func Test_EnsureCLIShouldRespectCliPathInEnv(t *testing.T) {
	tempDir := testutil.CreateTempDir(t)
	tempFile := testutil.CreateTempFile(tempDir, t)
	err := environment.SetCliPath(tempFile.Name())
	if err != nil {
		t.Fatal(t, "Couldn't set cli path in environment")
	}

	EnsureReadyForAnalysisAndWait()

	assert.Equal(t, tempFile.Name(), environment.CliPath())
}

func Test_isOutdatedCli_DetectsOutdatedCli(t *testing.T) {
	testutil.IntegTest(t)

	// prepare user directory with OS specific dummy CLI binary
	temp := testutil.CreateTempDir(t)
	file := testutil.CreateTempFile(temp, t)

	err := environment.SetCliPath(file.Name())
	if err != nil {
		t.Fatal(t, "Failed to set cli path to the temp cli file")
	}

	outdatedTime := time.Now().Add(-time.Hour*24*4 + 1)
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
	testutil.IntegTest(t)

	// prepare user directory with OS specific dummy CLI binary
	temp := testutil.CreateTempDir(t)
	file := testutil.CreateTempFile(temp, t)
	err := environment.SetCliPath(file.Name())
	if err != nil {
		t.Fatal(t, "Failed to set cli path to the temp cli file")
	}

	latestTime := time.Now().Add(time.Hour * 24 * 4)
	err = os.Chtimes(file.Name(), latestTime, latestTime)
	if err != nil {
		t.Fatal(t, "Failed to set the access and modification times of the temp cli file")
	}

	// act
	isOutdated := isOutdatedCli()

	// assert
	assert.False(t, isOutdated)
}

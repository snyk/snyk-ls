package preconditions

import (
	"os"
	"testing"

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
	err := environment.SetCliPath("testCliPath")
	if err != nil {
		t.Fatal(t, "Couldn't set cli path in environment")
	}
	temp, err := os.MkdirTemp("", "snyk-cli-test")
	if err != nil {
		t.Fatal(t, "Couldn't create test directory")
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(temp)

	EnsureReadyForAnalysisAndWait()

	assert.Equal(t, "testCliPath", environment.CliPath())
}

package testsupport

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GitCommandForTestRepo_DisablesSigning(t *testing.T) {
	cmd := GitCommandForTestRepo(t.TempDir(), "commit", "-m", "test")

	assert.Contains(t, cmd.Args, "commit.gpgsign=false")
	assert.Contains(t, cmd.Args, "tag.gpgsign=false")
}

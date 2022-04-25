package exec

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertCmd(t *testing.T, expectedArgs []string, actualCmd *exec.Cmd) {
	t.Helper()

	actualArgs := actualCmd.Args[1:]

	assert.Equal(t, expectedArgs, actualArgs)
}

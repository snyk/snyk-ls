package environment

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	Load()
}

func TestToken(t *testing.T) {
	t.Setenv(snykTokenKey, "")
	_ = os.Setenv(snykTokenKey, "test")

	assert.NotEqual(t, "", Token())
}

func Test_SnykCodeAnalysisTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	_ = os.Setenv(snykCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	assert.Equal(t, duration, SnykCodeAnalysisTimeout())
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	duration, _ := time.ParseDuration("10m")
	assert.Equal(t, duration, SnykCodeAnalysisTimeout())
}

func Test_updatePath(t *testing.T) {
	t.Setenv("PATH", "a")
	updatePath("b")
	assert.Equal(t, "a"+string(os.PathListSeparator)+"b", os.Getenv("PATH"))
}

func Test_loadFile(t *testing.T) {
	t.Setenv("A", "")
	t.Setenv("C", "")
	os.Unsetenv("A")
	os.Unsetenv("C")
	envData := []byte("A=B\nC=D")
	file, err := os.CreateTemp(".", "config_test_loadFile")
	if err != nil {
		assert.Fail(t, "Couldn't create temp file", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}(file)
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	_, _ = file.Write(envData)
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}

	loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))
}

func TestSetToken(t *testing.T) {
	oldToken := Token()
	err := SetToken("asdf")
	assert.NoError(t, err)
	assert.Equal(t, Token(), "asdf")
	_ = SetToken(oldToken)
}

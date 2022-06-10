package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetToken(t *testing.T) {
	SetCurrentConfig(New()) // can't use testutil here because of cyclical imports
	oldToken := CurrentConfig().Token()
	err := CurrentConfig().SetToken("asdf")
	assert.NoError(t, err)
	assert.Equal(t, CurrentConfig().Token(), "asdf")
	_ = CurrentConfig().SetToken(oldToken)
}

func TestToken(t *testing.T) {
	t.Setenv(SnykTokenKey, "test")
	c := New()
	assert.NotEqual(t, "", c.Token())
}

func Test_SnykCodeAnalysisTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
}

func Test_SnykCodeAnalysisTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	t.Setenv(snykCodeTimeoutKey, "")
	duration, _ := time.ParseDuration("10m")
	assert.Equal(t, duration, snykCodeAnalysisTimeoutFromEnv())
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

	CurrentConfig().loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))
}

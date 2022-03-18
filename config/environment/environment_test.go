package environment

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func init() {
	Load()
}

func TestToken(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv(snykTokenKey, "test")

	assert.NotEqual(t, "", Token())
}

func Test_SnykCodeTimeoutReturnsTimeoutFromEnvironment(t *testing.T) {
	_ = os.Setenv(snykCodeTimeoutKey, "1s")
	duration, _ := time.ParseDuration("1s")
	assert.Equal(t, duration, SnykCodeTimeout())
}

func Test_SnykCodeTimeoutReturnsDefaultIfNoEnvVariableFound(t *testing.T) {
	os.Clearenv()
	duration, _ := time.ParseDuration("10m")
	assert.Equal(t, duration, SnykCodeTimeout())
}

func Test_addSnykCliPathToEnv_should_find_cli_and_add_path_to_env(t *testing.T) {
	os.Clearenv()
	temp, err := os.MkdirTemp("", "snyk-cli-test")
	if err != nil {
		assert.Fail(t, "Couldn't create test directory")
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(temp)

	cliFile := createDummyCliFile(t, temp)
	err = os.Setenv("PATH", temp)
	if err != nil {
		assert.Fail(t, "Couldn't update PATH")
	}

	addSnykCliPathToEnv()

	assert.Equal(t, cliFile, os.Getenv(cliPathKey))
}

func Test_addSnykCliPathToEnv_should_respect_cli_path_in_env(t *testing.T) {
	os.Clearenv()
	err := os.Setenv(cliPathKey, "testCliPath")
	if err != nil {
		assert.Fail(t, "Couldn't set cli path in environment")
	}
	temp, err := os.MkdirTemp("", "snyk-cli-test")
	if err != nil {
		assert.Fail(t, "Couldn't create test directory")
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(temp)

	createDummyCliFile(t, temp)
	err = os.Setenv("PATH", temp)
	if err != nil {
		assert.Fail(t, "Couldn't update PATH")
	}

	addSnykCliPathToEnv()

	assert.Equal(t, "testCliPath", os.Getenv(cliPathKey))
}

func createDummyCliFile(t *testing.T, temp string) string {
	cliName := getSnykFileName()
	cliFile, err := os.Create(filepath.Join(temp, cliName))
	if err != nil {
		assert.Fail(t, "Couldn't create dummy cli file")
	}
	err = cliFile.Chmod(0770)
	if err != nil {
		assert.Fail(t, "Couldn't make dummy cli file executable")
	}

	_, err = cliFile.Write([]byte("huhu"))
	if err != nil {
		assert.Fail(t, "Can't write dummy data to cli file")
	}
	_ = cliFile.Close()
	return cliFile.Name()
}

func Test_updatePath(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("PATH", "a")
	updatePath("b")
	assert.Equal(t, "a"+string(os.PathListSeparator)+"b", os.Getenv("PATH"))
}

func Test_loadFile(t *testing.T) {
	os.Clearenv()
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

	os.Clearenv()
}

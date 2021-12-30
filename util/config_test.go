package util

import (
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func init() {
	Load()
}

func TestToken(t *testing.T) {
	os.Clearenv()
	os.Setenv(snykTokenKey, "test")

	assert.NotEqual(t, "", Token())
}

func Test_addSnykCliPathToEnv_should_find_cli_and_add_path_to_env(t *testing.T) {
	os.Clearenv()
	temp, err := os.MkdirTemp("", "snyk-cli-test")
	if err != nil {
		assert.Fail(t, "Couldn't create test directory")
	}
	defer os.RemoveAll(temp)
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
	defer os.RemoveAll(temp)
	createDummyCliFile(t, temp)
	err = os.Setenv("PATH", temp)
	if err != nil {
		assert.Fail(t, "Couldn't update PATH")
	}

	addSnykCliPathToEnv()

	assert.Equal(t, "testCliPath", os.Getenv(cliPathKey))
}

func createDummyCliFile(t *testing.T, temp string) string {
	cliName := "snyk"
	if runtime.GOOS == "windows" {
		cliName += ".exe"
	}
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
	cliFile.Close()
	return cliFile.Name()
}

func Test_updatePath(t *testing.T) {
	os.Clearenv()
	os.Setenv("PATH", "a")
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
	defer file.Close()
	defer os.Remove(file.Name())
	if err != nil {
		assert.Fail(t, "Couldn't create test file")
	}
	file.Write(envData)
	if err != nil {
		assert.Fail(t, "Couldn't write to test file")
	}

	loadFile(file.Name())

	assert.Equal(t, "B", os.Getenv("A"))
	assert.Equal(t, "D", os.Getenv("C"))

	os.Clearenv()
}

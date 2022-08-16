package testutil

import (
	"os"
	"testing"
)

func GetEnvironmentToken() string {
	return os.Getenv("SNYK_TOKEN")
}

func SetEnvOrFail(t *testing.T, key string, value string) {
	err := os.Setenv(key, value)
	if err != nil {
		t.Fatal(err)
	}
}

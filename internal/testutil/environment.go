package testutil

import "os"

func GetEnvironmentToken() string {
	return os.Getenv("SNYK_TOKEN")
}

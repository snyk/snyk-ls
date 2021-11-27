package util

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var CliPath = "snyk"

func SetupCLI() (string, error) {
	path := "snyk"
	_, err := exec.Command("snyk", "--help").CombinedOutput()
	if err != nil {
		r, _ := http.Get("https://static.snyk.io/cli/latest/snyk-macos")
		var bytes []byte
		r.Body.Read(bytes)
		r.Body.Close()
		downloadedCLI := os.Getenv("SNYK_PATH") + "snyk"
		err = os.WriteFile(downloadedCLI, bytes, 770)
		if err != nil {
			return "", err
		}
		path, err = filepath.Abs(downloadedCLI)
		if err != nil {
			return "", err
		}
	}
	return path, nil
}

package util

import (
	"net/http"
	"os"
	"os/exec"
)

var CliPath = "snyk"

func SetupCLI() (string, error) {
	_, err := exec.Command("snyk", "--help").CombinedOutput()
	if err == nil {
		return CliPath, nil
	}

	snykDir := os.Getenv("HOME") + "/.snyk"
	downloadedCLI := snykDir + "/snyk"

	r, _ := http.Get("https://static.snyk.io/cli/latest/snyk-macos")
	var bytes []byte
	r.Body.Read(bytes)
	r.Body.Close()
	os.Mkdir(snykDir, 0770)
	err = os.WriteFile(downloadedCLI, bytes, 0770)
	if err != nil {
		return CliPath, err
	}
	CliPath = downloadedCLI
	return CliPath, nil
}

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/adrg/xdg"
)

type Discovery struct{}

// LookPath searches for the Snyk CLI executable in the directories named by the PATH environment variable.
func (d *Discovery) LookPath() (string, error) {
	path, err := exec.LookPath(executableName)
	if err != nil {
		return "", fmt.Errorf("unable to find %s in PATH: %s", executableName, err)
	}
	return path, nil
}

// LookUserDir searches for the Snyk CLI executable in the  XDG_DATA_HOME/snyk-ls directory.
func (d *Discovery) LookUserDir() (string, error) {
	path := filepath.Join(xdg.DataHome, "snyk-ls", executableName)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("unable to find %s in user directory", executableName)
}

// ExecutableName returns OS specific filename for Snyk CLI.
func (d *Discovery) ExecutableName() string {
	return executableName
}

// DownloadURL returns OS specific download url for Snyk CLI.
func (d *Discovery) DownloadURL(r *Release) (string, error) {
	if r == nil {
		return "", fmt.Errorf("release cannot be nil")
	}
	return r.downloadURL(), nil
}

// ChecksumURL returns OS specific checksum url for Snyk CLI.
func (d *Discovery) ChecksumURL(r *Release) (string, error) {
	if r == nil {
		return "", fmt.Errorf("release cannot be nil")
	}
	return r.checksumURL(), nil
}

package config

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/adrg/xdg"
	"github.com/rs/zerolog/log"
)

var defaultDirs = []string{
	xdg.Home,
	"/usr/lib",
	"/usr/java",
	"/opt",
	"/Library",
	"C:\\Program Files",
	"C:\\Program Files (x86)",
}

func (c *Config) determineJavaHome() {
	method := "determineJavaHome"
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		c.updatePath(javaHome + string(os.PathSeparator) + "bin")
	} else {
		java := c.findBinary(getJavaBinaryName())
		absJavaPath, err := filepath.Abs(java)
		if err != nil {
			log.Warn().Str("method", method).
				Err(err).
				Str("path", java).
				Msg("couldn't get absolute filepath for found java exec")
		}
		if absJavaPath != "" {
			c.updatePath(absJavaPath)
			err = os.Setenv("JAVA_HOME", filepath.Dir(filepath.Dir(java)))
			if err != nil {
				log.Warn().Str("method", method).Msg("couldn't add java home to environment")
			}
		}
	}
}

func getJavaBinaryName() string {
	javaBinary := "java"
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == windows {
		javaBinary = "java.exe"
	}
	return javaBinary
}

func getMavenBinaryName() string {
	mavenBinary := "mvn"
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == windows {
		mavenBinary += ".exe"
	}
	return mavenBinary
}

func (c *Config) findBinary(binaryName string) string {
	path, _ := exec.LookPath(binaryName)
	if path != "" {
		return path
	}
	return c.FindBinaryInDirs(binaryName)
}

func (c *Config) FindBinaryInDirs(binaryName string) (foundJavaPath string) {
	method := "FindBinaryInDirs"
	for _, dir := range defaultDirs {
		_, err := os.Stat(dir)
		if err != nil {
			log.Info().Str("method", method).Msg("no java dir found in " + dir)
			continue
		}
		var foundFilePaths []string
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if filepath.Base(path) == binaryName {
				foundFilePaths = append(foundFilePaths, path)
				log.Debug().Str("method", "FindBinaryInDirs").Msgf("found: %s", path)
			}
			return err
		})
		if err != nil {
			return ""
		}
		count := len(foundFilePaths)
		if count > 0 {
			// take newest, as the dirwalk is lexical
			foundJavaPath = foundFilePaths[count-1]
		}
	}
	return foundJavaPath
}

package config

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
)

func (c *Config) determineJavaHome() {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		c.updatePath(javaHome + string(os.PathSeparator) + "bin")
		return
	}
	java := c.findBinary(getJavaBinaryName())
	c.updatePath(java)
	_ = os.Setenv("JAVA_HOME", filepath.Dir(filepath.Dir(java)))
}

func (c *Config) determineMavenHome() {
	mavenHome := os.Getenv("MAVEN_HOME")
	if mavenHome != "" {
		c.updatePath(mavenHome + string(os.PathSeparator) + "bin")
		return
	}
	path := c.findBinary(getMavenBinaryName())
	c.updatePath(filepath.Dir(path))
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
	log.Debug().Str("method", "findBinary").Msgf("searching for %s", binaryName)
	path, _ := exec.LookPath(binaryName)
	if path != "" {
		return path
	}
	foundPath := c.FindBinaryInDirs(binaryName)
	log.Debug().Str("method", "findBinary").Msgf("found: %s", foundPath)
	return foundPath
}

func (c *Config) FindBinaryInDirs(binaryName string) (foundPath string) {
	method := "FindBinaryInDirs"
	for _, dir := range c.defaultDirs {
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
			foundPath = foundFilePaths[count-1]
		}
	}
	return foundPath
}

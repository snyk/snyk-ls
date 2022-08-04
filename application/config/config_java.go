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

var javaDirs = []string{
	xdg.Home + "/.sdkman/candidates/java/current",
	"/usr/lib/jvm",
	"/usr/java",
	"/opt",
	"/Library",
	"C:\\Program Files\\Java",
	"C:\\Program Files (x86)\\Java",
}

func (c *Config) determineJavaHome(method string) {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		c.updatePath(javaHome + string(os.PathSeparator) + "bin")
	} else {
		java := c.findJava()
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

func (c *Config) findJava() string {
	javaBinary := getJavaBinaryName()
	path, _ := exec.LookPath(javaBinary)
	if path != "" {
		return path
	}
	return c.FindJavaInDirs()
}

func getJavaBinaryName() string {
	javaBinary := "java"
	if //goland:noinspection GoBoolExpressions
	runtime.GOOS == windows {
		javaBinary = "java.exe"
	}
	return javaBinary
}

func (c *Config) FindJavaInDirs() (foundJavaPath string) {
	method := "FindJavaInDirs"
	for _, dir := range javaDirs {
		_, err := os.Stat(dir)
		if err != nil {
			log.Info().Str("method", method).Msg("no java dir found in " + dir)
			continue
		}
		var foundJavaFilePaths []string
		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			javaBinary := getJavaBinaryName()
			if filepath.Base(path) == javaBinary {
				foundJavaFilePaths = append(foundJavaFilePaths, path)
				log.Debug().Str("method", "FindJavaInDirs").Msgf("found: %s", path)
			}
			return err
		})
		if err != nil {
			return ""
		}
		count := len(foundJavaFilePaths)
		if count > 0 {
			// take newest, as the dirwalk is lexical
			foundJavaPath = foundJavaFilePaths[count-1]
		}
	}
	return foundJavaPath
}

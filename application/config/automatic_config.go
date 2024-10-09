/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func (c *Config) determineJavaHome() {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		c.Logger().Debug().Str("method", "determineJavaHome").Msgf("using JAVA_HOME from env %s", javaHome)
		configuration.UpdatePath(javaHome+string(os.PathSeparator)+"bin", false)
		return
	}
	foundPath := c.FindBinaryInDirs(getJavaBinaryName())
	if foundPath == "" {
		return
	}
	path, done := c.normalizePath(foundPath)
	if done {
		return
	}
	c.Logger().Debug().Str("method", "determineJavaHome").Msgf("detected java binary at %s", path)
	binDir := filepath.Dir(path)
	javaHome = filepath.Dir(binDir)
	configuration.UpdatePath(binDir, false)
	c.Logger().Debug().Str("method", "determineJavaHome").Msgf("setting JAVA_HOME to %s", javaHome)
	_ = os.Setenv("JAVA_HOME", javaHome)
}

func (c *Config) normalizePath(foundPath string) (string, bool) {
	path, err := filepath.EvalSymlinks(foundPath)
	if err != nil {
		c.Logger().Err(err).Msg("could not resolve symlink to binary")
		return "", true
	}
	path, err = filepath.Abs(path)
	if err != nil {
		c.Logger().Err(err).Msg("could not resolve absolute path of binary")
		return "", true
	}
	return path, false
}

func (c *Config) mavenDefaults() {
	// explicitly and always use headless mode
	mavenOptsVarName := "MAVEN_OPTS"
	mavenOpts := os.Getenv(mavenOptsVarName)
	headless := "-Djava.awt.headless=true"
	if !strings.Contains(mavenOpts, headless) {
		mavenOpts = fmt.Sprintf("%s %s", mavenOpts, headless)
	}
	_ = os.Setenv(mavenOptsVarName, mavenOpts)

	mavenHome := os.Getenv("MAVEN_HOME")
	if mavenHome != "" {
		configuration.UpdatePath(mavenHome+string(os.PathSeparator)+"bin", false)
		return
	}
	foundPath := c.findBinary(getMavenBinaryName())
	if foundPath == "" {
		return
	}
	path, done := c.normalizePath(foundPath)
	if done {
		return
	}
	configuration.UpdatePath(filepath.Dir(path), false)
	c.Logger().Debug().Str("method", "mavenDefaults").Msgf("detected maven binary at %s", path)
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
	c.Logger().Debug().Str("method", "findBinary").Msgf("searching for %s", binaryName)
	path, _ := exec.LookPath(binaryName)
	if path != "" {
		return path
	}
	foundPath := c.FindBinaryInDirs(binaryName)
	c.Logger().Debug().Str("method", "findBinary").Msgf("found: %s", foundPath)
	return foundPath
}

func (c *Config) FindBinaryInDirs(binaryName string) (foundPath string) {
	method := "FindBinaryInDirs"
	var foundFilePaths []string
	for _, dir := range c.defaultDirs {
		_, err := os.Stat(dir)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if filepath.Base(path) == binaryName && d.Type().IsRegular() {
				foundFilePaths = append(foundFilePaths, path)
				c.Logger().Trace().Str("method", method).Msgf("found '%s' in '%s'", binaryName, path)
			}
			return err
		})
		count := len(foundFilePaths)
		if count > 0 {
			// take newest, as the dirwalk is lexical
			foundPath = foundFilePaths[count-1]
			c.Logger().Debug().Str("method", method).Msgf("using '%s' in '%s'", binaryName, foundPath)
		}
	}
	return foundPath
}

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
		log.Debug().Str("method", "determineJavaHome").Msgf("found javaHome %s in env", javaHome)
		c.updatePath(javaHome + string(os.PathSeparator) + "bin")
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
	log.Debug().Str("method", "determineJavaHome").Msgf("found java binary at %s", path)
	binDir := filepath.Dir(path)
	javaHome = filepath.Dir(binDir)
	c.updatePath(binDir)
	log.Debug().Str("method", "determineJavaHome").Msgf("setting java home to %s", javaHome)
	_ = os.Setenv("JAVA_HOME", javaHome)
}

func (c *Config) normalizePath(foundPath string) (string, bool) {
	path, err := filepath.EvalSymlinks(foundPath)
	if err != nil {
		log.Err(err).Msg("could not resolve symlink to binary")
		return "", true
	}
	path, err = filepath.Abs(path)
	if err != nil {
		log.Err(err).Msg("could not resolve absolute path of binary")
		return "", true
	}
	return path, false
}

func (c *Config) determineMavenHome() {
	mavenHome := os.Getenv("MAVEN_HOME")
	if mavenHome != "" {
		c.updatePath(mavenHome + string(os.PathSeparator) + "bin")
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
	var foundFilePaths []string
	for _, dir := range c.defaultDirs {
		_, err := os.Stat(dir)
		if err != nil {
			log.Info().Str("method", method).Msg("no java dir found in " + dir)
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if filepath.Base(path) == binaryName {
				foundFilePaths = append(foundFilePaths, path)
				log.Debug().Str("method", "FindBinaryInDirs").Msgf("found: %s", path)
			}
			return err
		})
		count := len(foundFilePaths)
		if count > 0 {
			// take newest, as the dirwalk is lexical
			foundPath = foundFilePaths[count-1]
		}
	}
	return foundPath
}

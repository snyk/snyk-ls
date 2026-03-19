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

	"github.com/adrg/xdg"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/envvars"

	"github.com/snyk/snyk-ls/internal/types"
)

func DetermineJavaHome(conf configuration.Configuration, logger *zerolog.Logger) {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		logger.Debug().Str("method", "determineJavaHome").Msgf("using JAVA_HOME from env %s", javaHome)
		envvars.UpdatePath(javaHome+string(os.PathSeparator)+"bin", false)
		return
	}
	foundPath := findBinaryInDirs(conf, logger, getJavaBinaryName())
	if foundPath == "" {
		return
	}
	path, done := normalizePath(logger, foundPath)
	if done {
		return
	}
	logger.Debug().Str("method", "determineJavaHome").Msgf("detected java binary at %s", path)
	binDir := filepath.Dir(path)
	javaHome = filepath.Dir(binDir)
	envvars.UpdatePath(binDir, false)
	logger.Debug().Str("method", "determineJavaHome").Msgf("setting JAVA_HOME to %s", javaHome)
	_ = os.Setenv("JAVA_HOME", javaHome)
}

func normalizePath(logger *zerolog.Logger, foundPath string) (string, bool) {
	path, err := filepath.EvalSymlinks(foundPath)
	if err != nil {
		logger.Err(err).Msg("could not resolve symlink to binary")
		return "", true
	}
	path, err = filepath.Abs(path)
	if err != nil {
		logger.Err(err).Msg("could not resolve absolute path of binary")
		return "", true
	}
	return path, false
}

func MavenDefaults(conf configuration.Configuration, logger *zerolog.Logger) {
	mavenOptsVarName := "MAVEN_OPTS"
	mavenOpts := os.Getenv(mavenOptsVarName)
	headless := "-Djava.awt.headless=true"
	if !strings.Contains(mavenOpts, headless) {
		mavenOpts = fmt.Sprintf("%s %s", mavenOpts, headless)
	}
	_ = os.Setenv(mavenOptsVarName, mavenOpts)

	mavenHome := os.Getenv("MAVEN_HOME")
	if mavenHome != "" {
		envvars.UpdatePath(mavenHome+string(os.PathSeparator)+"bin", false)
		return
	}
	foundPath := findBinary(conf, logger, getMavenBinaryName())
	if foundPath == "" {
		return
	}
	path, done := normalizePath(logger, foundPath)
	if done {
		return
	}
	envvars.UpdatePath(filepath.Dir(path), false)
	logger.Debug().Str("method", "mavenDefaults").Msgf("detected maven binary at %s", path)
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

func findBinary(conf configuration.Configuration, logger *zerolog.Logger, binaryName string) string {
	logger.Debug().Str("method", "findBinary").Msgf("searching for %s", binaryName)
	path, _ := exec.LookPath(binaryName)
	if path != "" {
		return path
	}
	foundPath := findBinaryInDirs(conf, logger, binaryName)
	logger.Debug().Str("method", "findBinary").Msgf("found: %s", foundPath)
	return foundPath
}

func findBinaryInDirs(conf configuration.Configuration, logger *zerolog.Logger, binaryName string) (foundPath string) {
	method := "findBinaryInDirs"
	var foundFilePaths []string
	paths, _ := conf.Get(configresolver.UserGlobalKey(types.SettingBinarySearchPaths)).([]string)
	for _, dir := range paths {
		_, err := os.Stat(dir)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if filepath.Base(path) == binaryName && d.Type().IsRegular() {
				foundFilePaths = append(foundFilePaths, path)
				logger.Trace().Str("method", method).Msgf("found '%s' in '%s'", binaryName, path)
			}
			return err
		})
	}
	count := len(foundFilePaths)
	if count > 0 {
		foundPath = foundFilePaths[count-1]
		logger.Debug().Str("method", method).Msgf("using '%s' in '%s'", binaryName, foundPath)
	}
	return foundPath
}

// getDefaultBinarySearchPaths returns the default system binary search paths based on the OS.
func getDefaultBinarySearchPaths() []string {
	//goland:noinspection GoBoolExpressions
	if runtime.GOOS == "windows" {
		return []string{
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		}
	} else {
		return []string{
			filepath.Join(xdg.Home, ".sdkman"),
			"/usr/lib",
			"/usr/java",
			"/usr/local/bin",
			"/opt/homebrew/bin",
			"/opt",
			"/Library",
		}
	}
}

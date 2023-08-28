/*
 * © 2023 Snyk Limited
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

package oss

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/infrastructure/oss/parser"
)

var (
	packageScanSupportedExtensions = map[string]bool{
		".html": true,
		".htm":  true,
	}
	_ snyk.PackageScanner = (*CLIScanner)(nil)
)

func (cliScanner *CLIScanner) ScanPackages(
	ctx context.Context,
	config *config.Config,
	path string,
	content string,
) {
	cliScanner.packageScanMutex.Lock()
	defer cliScanner.packageScanMutex.Unlock()

	logger := config.Logger().With().Str("method", "CLIScanner.ScanPackages").Logger()

	if !cliScanner.isPackageScanSupported(path) {
		logger.Debug().Msgf("package scan not supported for %s", path)
		return
	}

	// parse given path & content
	dependencies, err := cliScanner.getDependencies(config, path, content)
	if err != nil {
		logger.Err(err).Msg("error parsing file")
		return
	}

	notCached := cliScanner.updateCachedDependencies(dependencies)

	if len(notCached) > 0 {
		commandFunc := func(_ []string) (deps []string) {
			for _, d := range notCached {
				deps = append(deps, d.ArtifactID+"@"+d.Version)
			}
			return cliScanner.prepareScanCommand(deps)
		}
		_, err := cliScanner.scanInternal(ctx, path, commandFunc)
		if err != nil {
			logger.Err(err).Msg("error scanning packages")
			return
		}
	}
	return
}

func (cliScanner *CLIScanner) getDependencies(config *config.Config, path string,
	content string) (dependencies []parser.Dependency, err error) {
	logger := config.Logger().With().Str("method", "CLIScanner.getDependencies").Logger()
	p := parser.NewParser(config, path)
	if content == "" {
		dependencies, err = p.Parse(path)
		if err != nil {
			logger.Err(err).Msg("error parsing file")
			return nil, err
		}
	} else {
		dependencies, err = p.ParseContent(content)
		if err != nil {
			logger.Err(err).Msg("error parsing content")
			return nil, err
		}
	}
	return dependencies, err
}

// updateCachedDependencies updates the packageIssueCache and returns the dependencies that are not cached
func (cliScanner *CLIScanner) updateCachedDependencies(dependencies []parser.Dependency) (notCached []parser.Dependency) {
	logger := cliScanner.config.Logger().With().Str("method", "CLIScanner.updateCachedDependencies").Logger()
	for _, dependency := range dependencies {
		key := dependency.ArtifactID + "@" + dependency.Version
		cached := cliScanner.packageIssueCache[key]
		if len(cached) == 0 {
			// we need a full scan
			logger.Trace().Str("dependency", dependency.String()).Msg("not cached")
			notCached = append(notCached, dependency)

		} else {
			logger.Trace().Str("dependency", dependency.String()).Msg("cached")
			cliScanner.removeVulnerabilityCountsFromCache(cached)
			// update ranges of issues in inlinevalue cache
			newCached := []snyk.Issue{}
			for _, issue := range cached {
				logger.Trace().Str("issue", issue.ID).
					Str("old range", issue.Range.String()).
					Str("new range", dependency.Range.String()).
					Msg("updating range")
				issue.Range = dependency.Range
				newCached = append(newCached, issue)
			}
			cliScanner.packageIssueCache[key] = newCached
			cliScanner.addVulnerabilityCountsToCache(newCached)
		}
	}
	return notCached
}

func (cliScanner *CLIScanner) isPackageScanSupported(path string) bool {
	return packageScanSupportedExtensions[strings.ToLower(filepath.Ext(path))]
}

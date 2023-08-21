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
)

func (cliScanner *CLIScanner) ScanPackages(
	ctx context.Context,
	config *config.Config,
	path string,
) (issues []snyk.Issue, err error) {
	logger := config.Logger().With().Str("method", "APIScanner.Scan").Logger()
	if !cliScanner.isPackageScanSupported(path) {
		return issues, nil
	}

	p := parser.NewParser(config, path)
	dependencies, err := p.Parse(path)
	if err != nil {
		logger.Err(err).Msg("error parsing file")
		return nil, err
	}

	commandFunc := func(_ []string) (deps []string) {
		for _, d := range dependencies {
			deps = append(deps, d.ArtifactID+"@"+d.Version)
		}
		return cliScanner.prepareScanCommand(deps)
	}

	return cliScanner.scanInternal(ctx, path, commandFunc)
}

func (cliScanner *CLIScanner) isPackageScanSupported(path string) bool {
	return packageScanSupportedExtensions[strings.ToLower(filepath.Ext(path))]
}

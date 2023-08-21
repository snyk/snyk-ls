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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type inlineValueMap map[string][]snyk.InlineValue

func (cliScanner *CLIScanner) GetInlineValues(path string, myRange snyk.Range) (result []snyk.InlineValue, err error) {
	logger := log.With().Str("method", "CLIScanner.GetInlineValues").Logger()
	logger.Debug().Str("path", path).Msg("called")

	if !cliScanner.scanned[path] && cliScanner.isPackageScanSupported(path) {
		logger.Debug().Str("path", path).Msg("not yet scanned")
		_, err := cliScanner.ScanPackages(context.Background(), config.CurrentConfig(), path)
		if err != nil {
			return nil, err
		}
	}

	inlineValues := cliScanner.inlineValues[path]
	result = filterInlineValuesForRange(inlineValues, myRange)
	logger.Debug().Str("path", path).Msgf("%d inlineValues found", len(result))
	return result, nil
}

func (cliScanner *CLIScanner) ClearInlineValues(path string) {
	logger := log.With().Str("method", "CLIScanner.ClearInlineValues").Logger()

	cliScanner.inlineValues[path] = nil
	cliScanner.scanned[path] = false
	logger.Debug().Str("path", path).Msg("called")
}

func filterInlineValuesForRange(inlineValues []snyk.InlineValue, myRange snyk.Range) (result []snyk.InlineValue) {
	if len(inlineValues) == 0 {
		return nil
	}

	for _, inlineValue := range inlineValues {
		if myRange.Overlaps(inlineValue.Range) {
			result = append(result, inlineValue)
		}
	}
	return result
}

func toInlineValueAndAddToCache(
	vci *VulnerabilityCountInformation,
	cache inlineValueMap,
	getDisplayTextFunc func(vci *VulnerabilityCountInformation) string,
) snyk.InlineValue {
	inlineValues := cache[vci.FilePath]

	if inlineValues == nil {
		inlineValues = []snyk.InlineValue{}
	}

	inlineValue := toInlineValue(vci, getDisplayTextFunc)
	inlineValues = append(inlineValues, inlineValue)

	cache[vci.FilePath] = inlineValues

	return inlineValue
}

func toInlineValue(
	vci *VulnerabilityCountInformation,
	getDisplayTextFunc func(vci *VulnerabilityCountInformation) string,
) snyk.InlineValue {
	text := getDisplayTextFunc(vci)
	value := snyk.InlineValue{
		Path:  vci.FilePath,
		Range: vci.Range,
		Text:  text,
	}
	return value
}

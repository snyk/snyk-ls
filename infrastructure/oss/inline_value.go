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
	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/domain/snyk"
)

type inlineValueMap map[string][]snyk.InlineValue

func (cliScanner *CLIScanner) GetInlineValues(path string, myRange snyk.Range) (result []snyk.InlineValue, err error) {
	logger := log.With().Str("method", "CLIScanner.GetInlineValues").Logger()
	logger.Debug().Str("path", path).Msg("called")

	inlineValues := cliScanner.inlineValues[path]
	result = filterInlineValuesForRange(inlineValues, myRange)
	logger.Debug().Str("path", path).Msgf("%d inlineValues found", len(result))
	return result, nil
}

func (cliScanner *CLIScanner) ClearInlineValues(path string) {
	logger := log.With().Str("method", "CLIScanner.ClearInlineValues").Logger()

	cliScanner.inlineValues[path] = nil
	logger.Debug().Str("path", path).Msg("called")
}

func filterInlineValuesForRange(inlineValues []snyk.InlineValue, myRange snyk.Range) (result []snyk.InlineValue) {
	if len(inlineValues) == 0 {
		return nil
	}

	for _, inlineValue := range inlineValues {
		if myRange.Overlaps(inlineValue.Range()) {
			result = append(result, inlineValue)
		}
	}
	return result
}

func addToCache(iv snyk.InlineValue, cache inlineValueMap) {
	cache[iv.Path()] = append(cache[iv.Path()], iv)
}

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
	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type inlineValueMap map[types.FilePath][]snyk.InlineValue

func (cliScanner *CLIScanner) GetInlineValues(path types.FilePath, myRange types.Range) (result []snyk.InlineValue, err error) {
	logger := cliScanner.config.Logger().With().Str("method", "CLIScanner.GetInlineValues").Logger()
	cliScanner.inlineValueMutex.RLock()
	inlineValues := cliScanner.inlineValues[path]
	cliScanner.inlineValueMutex.RUnlock()
	result = filterInlineValuesForRange(inlineValues, myRange)
	logger.Trace().Str("path", string(path)).Msgf("%d inlineValues found", len(result))
	return result, nil
}

func (cliScanner *CLIScanner) ClearInlineValues(path types.FilePath) {
	cliScanner.inlineValueMutex.Lock()
	cliScanner.inlineValues[path] = nil
	cliScanner.inlineValueMutex.Unlock()
}

func filterInlineValuesForRange(inlineValues []snyk.InlineValue, myRange types.Range) (result []snyk.InlineValue) {
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

func (cliScanner *CLIScanner) addToCache(iv snyk.InlineValue, cache inlineValueMap) {
	cliScanner.inlineValueMutex.Lock()
	cache[iv.Path()] = append(cache[iv.Path()], iv)
	cliScanner.inlineValueMutex.Unlock()
}

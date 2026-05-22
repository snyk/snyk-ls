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
	"path/filepath"

	"github.com/snyk/snyk-ls/domain/snyk"
	"github.com/snyk/snyk-ls/internal/types"
)

type inlineValueMap map[types.FilePath][]snyk.InlineValue

// inlineValuesPathKey normalizes paths used as inline-value cache keys so URI-derived
// paths (textDocument/inlineValue) and OSS issue paths agree on Windows (slash style, cleaning).
func inlineValuesPathKey(p types.FilePath) types.FilePath {
	if p == "" {
		return p
	}
	// ToSlash aligns Windows paths from URIs vs CLI; no-op on Unix-style paths.
	return types.FilePath(filepath.ToSlash(filepath.Clean(string(p))))
}

func (cliScanner *CLIScanner) GetInlineValues(path types.FilePath, myRange types.Range) (result []snyk.InlineValue, err error) {
	logger := cliScanner.engine.GetLogger().With().Str("method", "CLIScanner.GetInlineValues").Logger()
	path = inlineValuesPathKey(path)
	cliScanner.inlineValueMutex.RLock()
	inlineValues := cliScanner.inlineValues[path]
	cliScanner.inlineValueMutex.RUnlock()
	result = filterInlineValuesForRange(inlineValues, myRange)
	logger.Trace().Str("path", string(path)).Msgf("%d inlineValues found", len(result))
	return result, nil
}

func (cliScanner *CLIScanner) ClearInlineValues(path types.FilePath) {
	cliScanner.inlineValueMutex.Lock()
	cliScanner.inlineValues[inlineValuesPathKey(path)] = nil
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
	key := inlineValuesPathKey(iv.Path())
	cache[key] = append(cache[key], iv)
	cliScanner.inlineValueMutex.Unlock()
}

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

func (oss *Scanner) GetInlineValues(path string, myRange snyk.Range) (result []snyk.InlineValue, err error) {
	logger := log.With().Str("method", "GetInlineValues").Logger()
	logger.Debug().Str("path", path).Msg("called")

	inlineValues := oss.inlineValues[path]
	if len(inlineValues) == 0 {
		logger.Debug().Str("path", path).Msg("no inlineValues found")
		return result, nil
	}

	for _, inlineValue := range inlineValues {
		if myRange.Overlaps(inlineValue.Range) {
			logger.Debug().Str("path", path).Msg("found inlineValues")
			result = append(result, inlineValue)
		}
	}
	return result, nil
}

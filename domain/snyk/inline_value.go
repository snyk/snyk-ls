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

package snyk

import (
	"fmt"

	"github.com/snyk/snyk-ls/internal/types"
)

type InlineValue interface {
	Path() types.FilePath
	Range() types.Range
	Text() string
	fmt.Stringer
}

// InlineValueProvider provides inline values.
type InlineValueProvider interface {
	// GetInlineValues returns inline values for a given path and range.
	// This should be a very fast operation.
	GetInlineValues(path types.FilePath, myRange types.Range) ([]InlineValue, error)

	// ClearInlineValues clears inline values for a given path.
	ClearInlineValues(path types.FilePath)
}

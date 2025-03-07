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

package hover

import (
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/internal/product"
	"github.com/snyk/snyk-ls/internal/types"
)

type Context any

type Hover[T Context] struct {
	Id      string
	Range   types.Range
	Message string
	Context T // this normally contains snyk.Issue
}

type DocumentHovers struct {
	Path    types.FilePath
	Product product.Product
	Hover   []Hover[Context]
}

type Params struct {
	TextDocument sglsp.TextDocumentIdentifier `json:"textDocument"`
	Position     sglsp.Position               `json:"position"`
}

type MarkupContent struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Result struct {
	Contents MarkupContent `json:"contents"`
}

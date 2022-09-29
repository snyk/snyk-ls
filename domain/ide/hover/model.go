/*
 * Copyright 2022 Snyk Ltd.
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
)

type Context interface{}

type Hover[T Context] struct {
	Id      string
	Range   sglsp.Range
	Message string
	Context T
}

type DocumentHovers struct {
	Uri   sglsp.DocumentURI
	Hover []Hover[Context]
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

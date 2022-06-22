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

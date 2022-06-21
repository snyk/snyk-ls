package hover

import (
	sglsp "github.com/sourcegraph/go-lsp"
)

type Hover struct {
	Id      string
	Range   sglsp.Range
	Message string
}

type DocumentHovers struct {
	Uri   sglsp.DocumentURI
	Hover []Hover
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

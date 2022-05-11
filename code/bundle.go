package code

import (
	sglsp "github.com/sourcegraph/go-lsp"
)

const (
	maxFileSize               = 1024 * 1024
	maxBundleSize             = 1024 * 1024 * 4
	jsonOverheadRequest       = "{\"files\":{}}"
	jsonOverHeadRequestLength = len(jsonOverheadRequest)
	jsonUriOverhead           = "\"\":{}"
	jsonHashSizePerFile       = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead       = ",\"content\":\"\""
	jsonOverheadPerFile       = jsonUriOverhead + jsonContentOverhead
)

type Bundle struct {
	hash      string
	documents map[sglsp.DocumentURI]BundleFile
	size      int
}

func NewBundle() Bundle {
	return Bundle{
		documents: map[sglsp.DocumentURI]BundleFile{},
	}
}

func (b *Bundle) getSize() int {
	if len(b.documents) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.documents) - 1
	var size = jsonOverHeadRequestLength + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	// todo: calculate json payload length instead of summing up constant overheads
	return size + b.size
}

func (b *Bundle) hasContent() bool {
	return len(b.documents) > 0
}

func getTotalDocPayloadSize(documentURI string, content []byte) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(documentURI)) + len(content)
}

type BundleFile struct {
	Hash    string `json:"hash"`
	Content string `json:"content"`
}

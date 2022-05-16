package code

import (
	sglsp "github.com/sourcegraph/go-lsp"
)

const (
	maxFileSize               = 1024 * 1024
	maxUploadBatchSize        = 1024 * 1024 * 4
	jsonOverheadRequest       = "{\"files\":{}}"
	jsonOverHeadRequestLength = len(jsonOverheadRequest)
	jsonUriOverhead           = "\"\":{}"
	jsonHashSizePerFile       = "\"hash\":\"0123456789012345678901234567890123456789012345678901234567890123\""
	jsonContentOverhead       = ",\"content\":\"\""
	jsonOverheadPerFile       = jsonUriOverhead + jsonContentOverhead
)

type UploadBatch struct {
	hash      string
	documents map[sglsp.DocumentURI]BundleFile
	size      int
}

func NewUploadBatch() UploadBatch {
	return UploadBatch{
		documents: map[sglsp.DocumentURI]BundleFile{},
	}
}

//todo simplify the size computation
// maybe consider an addFile / canFitFile interface with proper error handling
func (b *UploadBatch) canFitFile(uri string, content []byte) bool {
	docPayloadSize := b.getTotalDocPayloadSize(uri, content)
	newSize := docPayloadSize + b.getSize()
	b.size += docPayloadSize
	return newSize < maxUploadBatchSize
}

func (b *UploadBatch) getTotalDocPayloadSize(documentURI string, content []byte) int {
	return len(jsonHashSizePerFile) + len(jsonOverheadPerFile) + len([]byte(documentURI)) + len(content)
}

func (b *UploadBatch) getSize() int {
	if len(b.documents) == 0 {
		return 0
	}
	jsonCommasForFiles := len(b.documents) - 1
	var size = jsonOverHeadRequestLength + jsonCommasForFiles // if more than one file, they are separated by commas in the req
	return size + b.size
}

func (b *UploadBatch) hasContent() bool {
	return len(b.documents) > 0
}

type BundleFile struct {
	Hash    string `json:"hash"`
	Content string `json:"content"`
}

package diagnostics

import (
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

var (
	testLens = sglsp.CodeLens{
		Range: sglsp.Range{},
		Command: sglsp.Command{
			Title:     "Test Command Title",
			Command:   "Test Command",
			Arguments: []interface{}{"Test Arg"},
		},
		Data: "test data",
	}
)

func Test_CodeLenses_shouldReturnNilWithNothingInCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	lenses, _ := GetCodeLenses(doc.URI)
	assert.Nil(t, lenses)
}

func Test_CodeLenses_shouldReturnLensesFromCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	codeLenseCache[doc.URI] = append([]sglsp.CodeLens{}, testLens)
	lenses, _ := GetCodeLenses(doc.URI)
	assert.Equal(t, codeLenseCache[doc.URI], lenses)
}

func Test_AddLens_shouldAddLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	AddLens(doc.URI, testLens)
	assert.Equal(t, testLens, codeLenseCache[doc.URI][0])
}

func Test_clearLenses_shouldEmptyLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	AddLens(doc.URI, testLens)
	ClearLenses(doc.URI)
	assert.Equal(t, []sglsp.CodeLens{}, codeLenseCache[doc.URI])
}

func Test_construct_shouldEmptyLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	AddLens(doc.URI, testLens)
	ClearLenses(doc.URI)
	assert.Equal(t, []sglsp.CodeLens{}, codeLenseCache[doc.URI])
}

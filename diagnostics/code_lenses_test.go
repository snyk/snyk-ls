package diagnostics

import (
	"os"
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/code"
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
	uri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	lenses, _ := GetCodeLenses(uri)
	assert.Nil(t, lenses)
}

func Test_CodeLenses_shouldReturnLensesFromCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	uri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	codeLenseCache[uri] = append([]sglsp.CodeLens{}, testLens)
	lenses, _ := GetCodeLenses(uri)
	assert.Equal(t, codeLenseCache[uri], lenses)
}

func Test_AddLens_shouldAddLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	uri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	AddLens(uri, testLens)
	assert.Equal(t, testLens, codeLenseCache[uri][0])
}

func Test_clearLenses_shouldEmptyLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	uri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	AddLens(uri, testLens)
	ClearLenses(uri)
	assert.Equal(t, []sglsp.CodeLens{}, codeLenseCache[uri])
}

func Test_construct_shouldEmptyLensCache(t *testing.T) {
	codeLenseCache = map[sglsp.DocumentURI][]sglsp.CodeLens{}
	uri, path := code.FakeDiagnosticUri()
	defer os.RemoveAll(path)

	AddLens(uri, testLens)
	ClearLenses(uri)
	assert.Equal(t, []sglsp.CodeLens{}, codeLenseCache[uri])
}

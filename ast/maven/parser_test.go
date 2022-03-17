package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

func TestCreateDependencyTree(t *testing.T) {
	var testPath, _ = filepath.Abs("testdata/pom.xml")
	var testContent, _ = os.ReadFile(testPath)
	doc := lsp.DocumentURI(testPath)
	parser := Parser{}
	tree := parser.Parse(string(testContent), doc)
	children := tree.Root.Children
	assert.Len(t, children, 2, "Should have extracted 2 deps from pom.xml")

	assert.Equal(t, 38, children[0].Line)
	assert.Equal(t, 15, children[0].StartChar)
	assert.Equal(t, 21, children[0].EndChar)

	assert.Equal(t, 43, children[1].Line)
	assert.Equal(t, 15, children[1].StartChar)
	assert.Equal(t, 21, children[1].EndChar)
}

package code

import (
	"testing"

	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

func Test_getSize(t *testing.T) {
	t.Run("returns overhead", func(t *testing.T) {
		bundle := NewUploadBatch()
		bundle.documents = map[sglsp.DocumentURI]BundleFile{
			"uri": {},
		}

		size := bundle.getSize()

		assert.Equal(t, 12, size)
	})

	t.Run("when empty bundle should return 0", func(t *testing.T) {
		bundle := NewUploadBatch()

		size := bundle.getSize()

		assert.Equal(t, 0, size)
	})
}

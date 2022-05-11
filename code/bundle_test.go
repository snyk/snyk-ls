package code

import (
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_getSize(t *testing.T) {
	t.Run("returns bundle size", func(t *testing.T) {
		bundle := NewBundle()
		bundle.documents = map[sglsp.DocumentURI]BundleFile{"uri": {}}

		size := bundle.getSize()
		// todo MAGIC NUMBER the get size method is a bit hard to follow, can we implement/test it differently?
		assert.Equal(t, 12, size)
	})

	t.Run("when empty bundle should return 0", func(t *testing.T) {
		bundle := NewBundle()

		size := bundle.getSize()

		assert.Equal(t, 0, size)
	})
}

func Test_IsSupportedLanguage_shouldReturnTrueForSupportedLanguages(t *testing.T) {
	documentURI := uri.PathToUri("C:\\some\\path\\Test.java")
	supported := IsSupported(&FakeSnykCodeApiService{}, documentURI)
	assert.True(t, supported)
}

func Test_IsSupportedLanguage_shouldReturnFalseForUnsupportedLanguages(t *testing.T) {
	documentURI := uri.PathToUri("C:\\some\\path\\Test.rs")
	supported := IsSupported(&FakeSnykCodeApiService{}, documentURI)
	assert.False(t, supported)
}

func Test_IsSupportedLanguage_shouldCacheSupportedExtensions(t *testing.T) {
	documentURI := uri.PathToUri("C:\\some\\path\\Test.rs")
	IsSupported(&FakeSnykCodeApiService{}, documentURI)
	assert.Equal(t, supportedExtensions.Length(), len(FakeFilters))
}

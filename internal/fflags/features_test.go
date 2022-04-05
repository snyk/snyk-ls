package fflags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFeatureFlags(t *testing.T) {
	ff, err := LoadFeatureFlags()

	assert.NoError(t, err)
	assert.Equal(t, "test-feature with value 555", ff.TestFeature)
}

func TestLoadFeatureFlags_brokenJSON(t *testing.T) {
	featuresEmbed = []byte("{{{broken-json")

	_, err := LoadFeatureFlags()
	assert.Error(t, err)
}

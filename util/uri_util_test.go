package util

import (
	"testing"

	"github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
)

func TestPathFromUri(t *testing.T) {
	assert.Equal(t, "asdf", PathFromUri("file://asdf"))
	assert.Equal(t, "asdf", PathFromUri("file:asdf"))
}

func TestPathToUri(t *testing.T) {
	assert.Equal(t, lsp.DocumentURI("file://asdf"), PathToUri("asdf"))
}

package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hash(t *testing.T) {
	assert.Equal(t,
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		Hash([]byte("hello\n")),
	)
}

func Test_hashLatin1File(t *testing.T) {
	dir, _ := os.Getwd()
	content, _ := os.ReadFile(filepath.Join(dir, "testdata", "pom.xml"))
	assert.Equal(t, "404134d7a7d5e7b3b5ef88de5b5f5333b3b2247828ef846e48034b564c625dfc", Hash(content))
}

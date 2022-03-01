package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_hash(t *testing.T) {
	assert.Equal(t,
		"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		Hash("hello\n"),
	)
}

package concurrency

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicBool_GetSet(t *testing.T) {
	b := AtomicBool{}
	assert.Equal(t, false, b.Get())

	b.Set(true)
	assert.Equal(t, true, b.Get())
}

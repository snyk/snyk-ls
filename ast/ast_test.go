package ast

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodeAddChild(t *testing.T) {
	var node = Node{}
	var child = Node{}
	node.Add(&child)
	assert.NotNil(t, node.Children)
	assert.Equal(t, &node, child.Parent)
}

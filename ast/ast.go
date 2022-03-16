package ast

import (
	"github.com/sourcegraph/go-lsp"
)

type Node struct {
	Line       int
	StartChar  int
	EndChar    int
	DocOffset  int64
	Parent     *Node
	Children   []*Node
	Name       string
	Value      string
	Attributes map[string]string
}

type Tree struct {
	Root     *Node
	Document lsp.DocumentURI
}

type Parser interface {
	Parse(content []byte, uri lsp.DocumentURI) Tree
}

type Visitor interface {
	visit(*Node)
}

func (n *Node) Accept(v Visitor) {
	v.visit(n)
}

func (n *Node) Add(child *Node) *Node {
	n.Children = append(n.Children, child)
	child.Parent = n
	return n
}

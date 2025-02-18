/*
 * © 2022 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ast

import "fmt"

type Node struct {
	Line                       int
	StartChar                  int
	EndChar                    int
	DocOffset                  int64
	Parent                     *Node
	Children                   []*Node
	Name                       string
	Value                      string
	Attributes                 map[string]string
	Tree                       *Tree
	LinkedParentDependencyNode *Node
}

type Tree struct {
	ParentTree *Tree
	Root       *Node
	Document   string
}

func (t *Tree) String() string {
	return fmt.Sprintf("Root=%s, Document=%s, ParentTree=%s", t.Root, t.Document, t.ParentTree)
}

func (t *Tree) DebugString() string {
	return t.String()
}

type Parser interface {
	Parse(content []byte, uri string) Tree
}

type Visitor interface {
	visit(*Node)
}

func (n *Node) Accept(v Visitor) {
	v.visit(n)
}

func (n *Node) String() string {
	return fmt.Sprintf("Name=%s, Value=%s, CodeFlowPositionInFile=%d:%d:%d, Tree=%s, Parent=%s, LinkedParentDependencyNode=%s", n.Name, n.Value, n.Line, n.StartChar, n.EndChar, n.Tree, n.Parent, n.LinkedParentDependencyNode)
}

func (n *Node) DebugString() string {
	return fmt.Sprintf("%s, DocOffset: %d, ChildrenCount: %d", n.String(), n.DocOffset, len(n.Children))
}

func (n *Node) Add(child *Node) *Node {
	n.Children = append(n.Children, child)
	child.Parent = n
	return n
}

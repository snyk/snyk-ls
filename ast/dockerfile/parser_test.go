/*
 * © 2025 Snyk Limited
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

package dockerfile

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_Parse_SingleFrom(t *testing.T) {
	logger := zerolog.Nop()
	parser := New(&logger)

	content := `FROM ubuntu:20.04
RUN apt-get update
COPY . /app
`
	tree := parser.Parse([]byte(content), "/test/Dockerfile")

	require.NotNil(t, tree)
	assert.Equal(t, "/test/Dockerfile", tree.Document)
	assert.Equal(t, "/test/Dockerfile", tree.Root.Name)

	// Should have one FROM node
	require.Len(t, tree.Root.Children, 1)
	fromNode := tree.Root.Children[0]
	assert.Equal(t, "FROM", fromNode.Name)
	assert.Equal(t, "ubuntu:20.04", fromNode.Value)
	assert.Equal(t, 0, fromNode.Line)
}

func TestParser_Parse_MultipleFrom(t *testing.T) {
	logger := zerolog.Nop()
	parser := New(&logger)

	content := `FROM node:14 as builder
WORKDIR /app
COPY package*.json ./
RUN npm install

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
`
	tree := parser.Parse([]byte(content), "/test/Dockerfile")

	require.NotNil(t, tree)

	// Should have two FROM nodes
	require.Len(t, tree.Root.Children, 2)

	firstFrom := tree.Root.Children[0]
	assert.Equal(t, "FROM", firstFrom.Name)
	assert.Equal(t, "node:14", firstFrom.Value)
	assert.Equal(t, 0, firstFrom.Line)

	secondFrom := tree.Root.Children[1]
	assert.Equal(t, "FROM", secondFrom.Name)
	assert.Equal(t, "nginx:alpine", secondFrom.Value)
	assert.Equal(t, 5, secondFrom.Line)
}

func TestParser_Parse_SkipScratch(t *testing.T) {
	logger := zerolog.Nop()
	parser := New(&logger)

	content := `FROM scratch
COPY --from=builder /app /app
`
	tree := parser.Parse([]byte(content), "/test/Dockerfile")

	require.NotNil(t, tree)

	// Should have no FROM nodes (scratch is skipped)
	assert.Len(t, tree.Root.Children, 0)
}

func TestParser_Parse_CaseInsensitive(t *testing.T) {
	logger := zerolog.Nop()
	parser := New(&logger)

	content := `from ubuntu:20.04
FROM alpine:3.14
FrOm golang:1.19
`
	tree := parser.Parse([]byte(content), "/test/Dockerfile")

	require.NotNil(t, tree)

	// Should have three FROM nodes
	require.Len(t, tree.Root.Children, 3)
	assert.Equal(t, "ubuntu:20.04", tree.Root.Children[0].Value)
	assert.Equal(t, "alpine:3.14", tree.Root.Children[1].Value)
	assert.Equal(t, "golang:1.19", tree.Root.Children[2].Value)
}

func TestParser_Parse_WithWindowsLineEndings(t *testing.T) {
	logger := zerolog.Nop()
	parser := New(&logger)

	content := "FROM ubuntu:20.04\r\nRUN apt-get update\r\n"
	tree := parser.Parse([]byte(content), "/test/Dockerfile")

	require.NotNil(t, tree)

	// Should have one FROM node
	require.Len(t, tree.Root.Children, 1)
	assert.Equal(t, "ubuntu:20.04", tree.Root.Children[0].Value)
}

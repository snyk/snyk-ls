/*
 * © 2023 Snyk Limited
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

package parser

import (
	"path/filepath"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/snyk"
)

type Dependency struct {
	GroupID    string
	ArtifactID string
	Version    string
	Range      snyk.Range
}

func (d Dependency) String() string {
	return d.GroupID + ":" + d.ArtifactID + ":" + d.Version
}

type DependencyParser interface {
	// Parse analyzes the given files contents and returns the found dependencies
	Parse(filePath string) (dependencies []Dependency, err error)
}

var parserConstructors = map[string]func(config *config.Config) DependencyParser{
	".html": func(config *config.Config) DependencyParser { return NewHTMLParser(config) },
	".htm":  func(config *config.Config) DependencyParser { return NewHTMLParser(config) },
}

func NewParser(config *config.Config, path string) DependencyParser {
	ext := filepath.Ext(path)
	parserConstructor := parserConstructors[ext]
	if parserConstructor == nil {
		return nil
	}
	return parserConstructor(config)
}

/*
 * © 2022-2024 Snyk Limited
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

package vcs

import (
	"github.com/go-git/go-git/v5"
)

var _ GitOps = (*GitWrapper)(nil)

type GitOps interface {
	PlainOpen(path string) (*git.Repository, error)
	PlainClone(path string, bare bool, options *git.CloneOptions) (*git.Repository, error)
}

type GitWrapper struct {
}

func (g *GitWrapper) PlainOpen(path string) (*git.Repository, error) {
	return git.PlainOpen(path)
}

func (g *GitWrapper) PlainClone(path string, bare bool, options *git.CloneOptions) (*git.Repository, error) {
	return git.PlainClone(path, bare, options)
}

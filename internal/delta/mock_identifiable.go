/*
 * © 2024 Snyk Limited
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

package delta

import "github.com/snyk/snyk-ls/internal/types"

var _ Identifiable = (*mockIdentifiable)(nil)
var _ Fingerprintable = (*mockIdentifiable)(nil)
var _ Locatable = (*mockIdentifiable)(nil)
var _ Pathable = (*mockIdentifiable)(nil)

type mockIdentifiable struct {
	globalIdentity string
	fingerprint    string
	isNew          bool
	ruleId         string
	path           types.FilePath
	contentRoot    types.FilePath
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
}

func (m *mockIdentifiable) GetContentRoot() types.FilePath {
	return m.contentRoot
}

func (m *mockIdentifiable) GetPath() types.FilePath {
	return m.path
}

func (m *mockIdentifiable) StartLine() int {
	return m.startLine
}

func (m *mockIdentifiable) EndLine() int {
	return m.endLine
}

func (m *mockIdentifiable) StartColumn() int {
	return m.startColumn
}

func (m *mockIdentifiable) EndColumn() int {
	return m.endColumn
}

func (m *mockIdentifiable) GetFingerprint() string {
	return m.fingerprint
}

func (m *mockIdentifiable) GetRuleID() string {
	return m.ruleId
}

func (m *mockIdentifiable) SetIsNew(isNew bool) {
	m.isNew = isNew
}

func (m *mockIdentifiable) GetIsNew() bool {
	return m.isNew
}

func (m *mockIdentifiable) GetGlobalIdentity() string {
	return m.globalIdentity
}

func (m *mockIdentifiable) SetGlobalIdentity(id string) {
	m.globalIdentity = id
}

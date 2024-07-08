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

type mockIdentifiable struct {
	globalIdentity string
	isNew          bool
}

func (m *mockIdentifiable) RuleId() string {
	//Not used, but needed for the interface
	panic("implement me")
}

func (m *mockIdentifiable) SetIsNew(isNew bool) {
	m.isNew = isNew
}

func (m *mockIdentifiable) IsNew() bool {
	return m.isNew
}

func (m *mockIdentifiable) GetGlobalIdentity() string {
	return m.globalIdentity
}

func (m *mockIdentifiable) SetGlobalIdentity(id string) {
	m.globalIdentity = id
}

/*
 * © 2026 Snyk Limited
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

package util

import "github.com/snyk/go-application-framework/pkg/configuration/configresolver"

// CoerceToLocalConfigField handles both in-memory *LocalConfigField (during session)
// and map[string]interface{} (after JSON deserialization on restart).
func CoerceToLocalConfigField(val any) (*configresolver.LocalConfigField, bool) {
	if lf, ok := val.(*configresolver.LocalConfigField); ok {
		return lf, lf != nil && lf.Changed
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, false
	}
	changed, _ := m["changed"].(bool)
	if !changed {
		return nil, false
	}
	return &configresolver.LocalConfigField{Value: m["value"], Changed: true}, true
}

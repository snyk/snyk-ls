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

package scanstates

// CompositeEmitter fans out scan state changes to multiple emitters.
type CompositeEmitter struct {
	emitters []ScanStateChangeEmitter
}

// NewCompositeEmitter creates a new CompositeEmitter that calls all given emitters on Emit.
func NewCompositeEmitter(emitters ...ScanStateChangeEmitter) *CompositeEmitter {
	return &CompositeEmitter{emitters: emitters}
}

func (c *CompositeEmitter) Emit(state StateSnapshot) {
	for _, e := range c.emitters {
		go e.Emit(state)
	}
}

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

import (
	"testing"

	"github.com/stretchr/testify/assert" // using testify for assertions
)

func TestFind_EmptyLists(t *testing.T) {
	f := NewFinder()
	_, _, err := f.Find([]Identifiable{}, []Identifiable{})

	assert.EqualError(t, err, "baselist or currentlist is empty")
}

func TestFind_MissingDiffer(t *testing.T) {
	f := NewFinder(WithEnricher(FindingsEnricher{}))
	_, _, err := f.Find(
		[]Identifiable{&mockIdentifiable{globalIdentity: "1"}},
		[]Identifiable{&mockIdentifiable{globalIdentity: "2"}})

	assert.EqualError(t, err, "findings differ not defined")
}

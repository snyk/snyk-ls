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

package float

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToFixed(t *testing.T) {
	testTable := []struct {
		input     float64
		precision int
		output    float64
	}{
		{1.23456789, 2, 1.23},                         // normal case, 2 decimal places
		{1.23446789, 3, 1.234},                        // normal case, 3 decimal places
		{1.245, 2, 1.25},                              // rounding case, 2 decimal places
		{1.23456789, 3, 1.235},                        // rounding case, 3 decimal places
		{9999999999999999.15, 2, 9999999999999999.15}, // large input fraction
		{3.40282346638528859811704183484516925440000000000000, 2, 3.40}, // large input precision
	}

	for _, s := range testTable {
		assert.Equal(t, s.output, ToFixed(s.input, s.precision))
	}
}

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

package oss

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestURLParseCachedCopy_sameRaw_distinctPointers_equalValue(t *testing.T) {
	const raw = "https://example.com/path?q=1"
	a, err := urlParseCachedCopy(raw)
	require.NoError(t, err)
	b, err := urlParseCachedCopy(raw)
	require.NoError(t, err)
	assert.Equal(t, a.String(), b.String())
	assert.NotSame(t, a, b, "each call should return an independent pointer")
}

func TestURLParseCachedCopy_parseError(t *testing.T) {
	_, err := urlParseCachedCopy("://invalid")
	assert.Error(t, err)
}

func TestCreateIssueURL_usesCache_distinctPointers(t *testing.T) {
	engine := testutil.UnitTest(t)
	u1 := CreateIssueURL(engine, "SNYK-JS-TEST")
	u2 := CreateIssueURL(engine, "SNYK-JS-TEST")
	require.NotNil(t, u1)
	require.NotNil(t, u2)
	assert.Equal(t, u1.String(), u2.String())
	assert.NotSame(t, u1, u2)
}

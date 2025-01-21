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

package summary

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_Summary_Html_getSummaryDetailsHtml(t *testing.T) {
	c := testutil.UnitTest(t)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	summaryPanel := htmlRenderer.GetSummaryHtml()

	// assert injectable style
	assert.Contains(t, summaryPanel, "${ideStyle}")
	// assert injectable script
	assert.Contains(t, summaryPanel, "${ideScript}")

	// assert Header section
	assert.Contains(t, summaryPanel, `class="snx-header`)
}

func Test_Summary_Html_getSummaryDetailsHtml_hasCSS(t *testing.T) {
	c := testutil.UnitTest(t)

	// invoke method under test
	htmlRenderer, err := NewHtmlRenderer(c)
	assert.NoError(t, err)
	summaryPanel := htmlRenderer.GetSummaryHtml()
	// assert css section
	assert.Contains(t, summaryPanel, ":root { font-size:10px; }")
}

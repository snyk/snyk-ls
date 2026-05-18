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

package oss

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestGetExtendedMessage_memoizationMatchesDirectBuild(t *testing.T) {
	extendedMessageCache.resetForTests()
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatMd)
	issue := sampleIssue()
	want := buildExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	got := GetExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	require.Equal(t, want, got)
	gotAgain := GetExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	assert.Equal(t, want, gotAgain)
}

func TestGetExtendedMessage_differentPackageNameNotDeduped(t *testing.T) {
	extendedMessageCache.resetForTests()
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatMd)
	issue := sampleIssue()
	a := GetExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, "pkg-a",
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	b := GetExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, "pkg-b",
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	require.NotEqual(t, a, b)
	assert.Contains(t, a, "pkg-a")
	assert.Contains(t, b, "pkg-b")
}

func TestGetExtendedMessage_concurrentSameArgs(t *testing.T) {
	extendedMessageCache.resetForTests()
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatMd)
	issue := sampleIssue()
	first := GetExtendedMessage(
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
	)
	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			g := GetExtendedMessage(
				issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
				issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
			)
			assert.Equal(t, first, g)
		}()
	}
	wg.Wait()
}

func TestGetExtendedMessage_cacheIsBounded(t *testing.T) {
	extendedMessageCache.resetForTests()
	c := testutil.UnitTest(t)
	c.SetFormat(config.FormatMd)
	issue := sampleIssue()

	for i := range maxExtendedMessageCacheEntries + 10 {
		_ = GetExtendedMessage(
			issue.Id+"-"+strconv.Itoa(i), issue.Title, issue.Description, issue.Severity, issue.PackageName,
			issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		)
	}

	assert.LessOrEqual(t, extendedMessageCache.len(), maxExtendedMessageCacheEntries)
}

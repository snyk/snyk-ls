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
	"sync"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
)

func TestGetExtendedMessage_memoizationMatchesDirectBuild(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingFormat), config.FormatMd)
	issue := sampleIssue()
	resolver := defaultResolver(t, engine)
	want := buildExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	got := GetExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	require.Equal(t, want, got)
	gotAgain := GetExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	assert.Equal(t, want, gotAgain)
}

func TestGetExtendedMessage_differentPackageNameNotDeduped(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingFormat), config.FormatMd)
	issue := sampleIssue()
	resolver := defaultResolver(t, engine)
	a := GetExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, "pkg-a",
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	b := GetExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, "pkg-b",
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	require.NotEqual(t, a, b)
	assert.Contains(t, a, "pkg-a")
	assert.Contains(t, b, "pkg-b")
}

func TestGetExtendedMessage_concurrentSameArgs(t *testing.T) {
	engine := testutil.UnitTest(t)
	engine.GetConfiguration().Set(configresolver.UserGlobalKey(types.SettingFormat), config.FormatMd)
	issue := sampleIssue()
	resolver := defaultResolver(t, engine)
	first := GetExtendedMessage(
		resolver, engine,
		issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
		issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
		nil,
	)
	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			g := GetExtendedMessage(
				resolver, engine,
				issue.Id, issue.Title, issue.Description, issue.Severity, issue.PackageName,
				issue.Identifiers.CVE, issue.Identifiers.CWE, issue.FixedIn,
				nil,
			)
			assert.Equal(t, first, g)
		}()
	}
	wg.Wait()
}

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

package code

import (
	"sync"
	"testing"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

// Test_SnykCodeApi_ConcurrentAccess_SameInstance verifies that calling SnykCodeApi
// from many goroutines on the SAME CodeConfig instance does not race and registers
// the URL exactly once (IDE-2169).
func Test_SnykCodeApi_ConcurrentAccess_SameInstance(t *testing.T) {
	const goroutines = 50
	const codeApiURL = "https://deeproxy.example.com"

	engine := testutil.UnitTest(t)
	configResolver := testutil.DefaultConfigResolver(engine)

	cc := &CodeConfig{
		orgForFolder:   "test-org",
		engine:         engine,
		codeApiUrl:     codeApiURL,
		configResolver: configResolver,
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			result := cc.SnykCodeApi()
			assert.Equal(t, codeApiURL, result)
		}()
	}
	wg.Wait()

	additionalURLs := engine.GetConfiguration().GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	count := 0
	for _, u := range additionalURLs {
		if u == codeApiURL {
			count++
		}
	}
	require.Equalf(t, 1, count,
		"expected codeApiURL exactly once in AUTHENTICATION_ADDITIONAL_URLS, got %d; slice: %v",
		count, additionalURLs)
}

// Test_SnykCodeApi_ConcurrentAccess_CrossInstance reproduces the production race:
// two SEPARATE *CodeConfig instances (as created by createCodeConfig for two different
// workspace folders) SHARE one engine configuration and call SnykCodeApi concurrently.
// With only a per-instance mutex the race detector fires; after the package-level lock
// fix it must pass cleanly (IDE-2169).
func Test_SnykCodeApi_ConcurrentAccess_CrossInstance(t *testing.T) {
	const goroutines = 50
	const urlA = "https://deeproxy-a.example.com"
	const urlB = "https://deeproxy-b.example.com"

	// Both CodeConfig instances share ONE engine, as production does when
	// createCodeConfig is called for two workspace folders of the same Scanner.
	engine := testutil.UnitTest(t)
	configResolver := testutil.DefaultConfigResolver(engine)

	ccA := &CodeConfig{
		orgForFolder:   "org-a",
		engine:         engine,
		codeApiUrl:     urlA,
		configResolver: configResolver,
	}
	ccB := &CodeConfig{
		orgForFolder:   "org-b",
		engine:         engine,
		codeApiUrl:     urlB,
		configResolver: configResolver,
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for range goroutines {
		go func() {
			defer wg.Done()
			result := ccA.SnykCodeApi()
			assert.Equal(t, urlA, result)
		}()
		go func() {
			defer wg.Done()
			result := ccB.SnykCodeApi()
			assert.Equal(t, urlB, result)
		}()
	}
	wg.Wait()

	additionalURLs := engine.GetConfiguration().GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	countA, countB := 0, 0
	for _, u := range additionalURLs {
		switch u {
		case urlA:
			countA++
		case urlB:
			countB++
		}
	}
	require.Equalf(t, 1, countA,
		"urlA must appear exactly once in AUTHENTICATION_ADDITIONAL_URLS, got %d; slice: %v",
		countA, additionalURLs)
	require.Equalf(t, 1, countB,
		"urlB must appear exactly once in AUTHENTICATION_ADDITIONAL_URLS, got %d; slice: %v",
		countB, additionalURLs)
}

// Test_SnykCodeApi_ConcurrentWithLocalEngine verifies that concurrent calls to
// SnykCodeApi (via CodeConfig) and updateCodeApiLocalEngine on the SAME shared
// engine configuration do not race (IDE-2169).
func Test_SnykCodeApi_ConcurrentWithLocalEngine(t *testing.T) {
	const goroutines = 25
	const codeApiURL = "https://deeproxy.example.com"
	const localEngineURL = "http://local.engine"

	// Prevent GetCodeApiUrlFromCustomEndpoint from returning early with the
	// DEEPROXY_API_URL env value instead of the local-engine URL from sastResponse.
	// Without this guard the test would never register localEngineURL in CI.
	// Mirrors the guard used in sast_local_engine_test.go:58.
	t.Setenv(config.DeeproxyApiUrlKey, "")

	engine := testutil.UnitTest(t)
	configResolver := testutil.DefaultConfigResolver(engine)

	cc := &CodeConfig{
		orgForFolder:   "test-org",
		engine:         engine,
		codeApiUrl:     codeApiURL,
		configResolver: configResolver,
	}

	mockedSastResponse := &sast_contract.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: sast_contract.LocalCodeEngine{
			AllowCloudUpload: false,
			Url:              localEngineURL,
			Enabled:          true,
		},
	}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for range goroutines {
		go func() {
			defer wg.Done()
			result := cc.SnykCodeApi()
			assert.Equal(t, codeApiURL, result)
		}()
		go func() {
			defer wg.Done()
			updateCodeApiLocalEngine(engine, mockedSastResponse)
		}()
	}
	wg.Wait()

	additionalURLs := engine.GetConfiguration().GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	countCode, countLocal := 0, 0
	for _, u := range additionalURLs {
		switch u {
		case codeApiURL:
			countCode++
		case localEngineURL:
			countLocal++
		}
	}
	require.Equalf(t, 1, countCode,
		"codeApiURL must appear exactly once in AUTHENTICATION_ADDITIONAL_URLS, got %d; slice: %v",
		countCode, additionalURLs)
	require.Equalf(t, 1, countLocal,
		"localEngineURL must appear exactly once in AUTHENTICATION_ADDITIONAL_URLS, got %d; slice: %v",
		countLocal, additionalURLs)
}

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

package fflags

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadFeatureFlags(t *testing.T) {
	ff, err := LoadFeatureFlags()

	assert.NoError(t, err)
	assert.Equal(t, "test-feature with value 555", ff.TestFeature)
}

// TestLoadFeatureFlags_brokenJSON calls parseFeatureFlags directly to verify
// JSON parse errors are propagated. The errCached branch in LoadFeatureFlags
// is unreachable in practice: the embedded asset is compiled in at build time,
// so a malformed features.json would be caught by TestLoadFeatureFlags first.
func TestLoadFeatureFlags_brokenJSON(t *testing.T) {
	_, err := parseFeatureFlags([]byte("{{{broken-json"))
	assert.Error(t, err)
}

// TestLoadFeatureFlags_concurrent exercises concurrent calls to LoadFeatureFlags.
// Package-level state is reset before launching goroutines so the test covers
// the once.Do initialisation path regardless of which tests ran before it.
func TestLoadFeatureFlags_concurrent(t *testing.T) {
	// Reset package-level state so this test exercises the once.Do init path,
	// not just the cached-read fast path.
	once = sync.Once{}
	cached = FeatureFlag{}
	errCached = nil

	const goroutines = 20

	var wg sync.WaitGroup
	results := make([]*FeatureFlag, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = LoadFeatureFlags()
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i])
		assert.Equal(t, "test-feature with value 555", results[i].TestFeature)
	}
}

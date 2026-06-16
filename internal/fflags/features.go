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

// Package fflags implements the feature flag functionality
package fflags

import (
	_ "embed"
	"encoding/json"
	"sync"
)

type FeatureFlag struct {
	TestFeature string `json:"test-feature,omitempty"`
}

var (
	//go:embed features.json
	featuresEmbed []byte

	once      sync.Once   //nolint:gochecknoglobals // legacy process-global state
	cached    FeatureFlag //nolint:gochecknoglobals // legacy process-global state
	errCached error
)

func parseFeatureFlags(data []byte) (FeatureFlag, error) {
	var ff FeatureFlag
	if err := json.Unmarshal(data, &ff); err != nil {
		return FeatureFlag{}, err
	}
	return ff, nil
}

// LoadFeatureFlags returns the parsed feature flags. The embedded JSON is
// unmarshalled exactly once; errCached is non-nil only if the embedded asset
// is malformed at build time, which TestLoadFeatureFlags would also catch.
func LoadFeatureFlags() (*FeatureFlag, error) {
	once.Do(func() {
		cached, errCached = parseFeatureFlags(featuresEmbed)
	})
	if errCached != nil {
		return nil, errCached
	}
	// Shallow copy is safe because FeatureFlag contains only value-typed fields
	// (strings). If a slice, map, or pointer is ever added, replace this with
	// an explicit deep copy to avoid sharing mutable state between callers.
	cp := cached
	return &cp, nil
}

/*
 * Copyright 2022 Snyk Ltd.
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
	_ "embed"
	"encoding/json"

	"github.com/rs/zerolog/log"
)

type FeatureFlag struct {
	TestFeature string `json:"test-feature,omitempty"`
}

var (
	//go:embed features.json
	featuresEmbed []byte
	featureFlag   FeatureFlag
)

func LoadFeatureFlags() (*FeatureFlag, error) {
	err := json.Unmarshal(featuresEmbed, &featureFlag)
	if err != nil {
		log.Err(err).Msg("Could not load baked in feature.json")
		return nil, err
	}
	return &featureFlag, nil
}

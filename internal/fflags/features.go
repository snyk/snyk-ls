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

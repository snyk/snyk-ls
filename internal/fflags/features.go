package fflags

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/snyk/snyk-ls/config/environment"
)

type FeatureFlag struct {
	TestFeature string `json:"test-feature,omitempty"`
}

var (
	//go:embed features.json
	featuresEmbed []byte
	featureFlag   FeatureFlag
	logger        = environment.Logger
)

func LoadFeatureFlags() (*FeatureFlag, error) {
	err := json.Unmarshal(featuresEmbed, &featureFlag)
	if err != nil {
		logger.
			WithField("method", "LoadFeatureFlags").
			WithError(err).
			Error(context.Background(), "Could not load baked in feature.json")
		return nil, err
	}
	return &featureFlag, nil
}

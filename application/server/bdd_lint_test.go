package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ide2418Requirements is a manually-maintained ratchet: extend it alongside
// each new feature file so it can't silently drift from real coverage.
var ide2418Requirements = []string{"M1"}

func Test_FeatureFiles_MapEveryRequirement(t *testing.T) {
	scenarios, err := parseFeatureDir("../../features")
	require.NoError(t, err)

	err = checkFeatureMappings(scenarios, ide2418Requirements)
	require.NoError(t, err)
}

// Test_FeatureFiles_ScenarioWithoutMapsAnchorFails exists so the lint itself can't become a ghost check that never actually fails anything.
func Test_FeatureFiles_ScenarioWithoutMapsAnchorFails(t *testing.T) {
	t.Run("scenario missing a maps anchor is reported", func(t *testing.T) {
		fixture := []byte(`Feature: fixture with a missing anchor

Scenario: a scenario with no maps anchor
  Given something
`)
		scenarios := parseFeatureScenarios("fixture.feature", fixture)
		require.Len(t, scenarios, 1)

		err := checkFeatureMappings(scenarios, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "a scenario with no maps anchor")
	})

	t.Run("maps anchor is still found across a Gherkin tag line", func(t *testing.T) {
		fixture := []byte(`Feature: fixture with a tag between the anchor and the scenario

  # maps: M1
  @sometag
Scenario: a tagged scenario mapped to M1
  Given something
`)
		scenarios := parseFeatureScenarios("fixture.feature", fixture)
		require.Len(t, scenarios, 1)
		assert.Equal(t, []string{"M1"}, scenarios[0].mapsToID)
	})

	t.Run("maps anchor is still found across a plain comment line", func(t *testing.T) {
		fixture := []byte(`Feature: fixture with a plain comment between the anchor and the scenario

  # maps: M1
  # a plain documentation comment, not a maps anchor
Scenario: a scenario mapped to M1 past a plain comment
  Given something
`)
		scenarios := parseFeatureScenarios("fixture.feature", fixture)
		require.Len(t, scenarios, 1)
		assert.Equal(t, []string{"M1"}, scenarios[0].mapsToID)
	})

	t.Run("requirement named by no scenario is reported", func(t *testing.T) {
		fixture := []byte(`Feature: fixture with partial coverage

  # maps: X1
Scenario: a scenario mapped to X1 only
  Given something
`)
		scenarios := parseFeatureScenarios("fixture.feature", fixture)
		require.Len(t, scenarios, 1)

		err := checkFeatureMappings(scenarios, []string{"X1", "X2"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "X2")
	})
}

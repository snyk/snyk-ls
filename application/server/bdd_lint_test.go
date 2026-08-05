package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ide2418Requirements lists the requirement IDs this repository's feature
// files are expected to name via `# maps:` anchors. It grows one checkpoint
// at a time: each of IDE-2418's checkpoints adds its own feature file plus
// the requirement IDs that file covers, in the same commit, so this list and
// the real coverage under features/ never drift apart.
var ide2418Requirements = []string{"M1"}

// Test_FeatureFiles_MapEveryRequirement asserts every scenario under
// features/ carries a `# maps: M<n>` anchor, and that every requirement
// currently claimed as covered (ide2418Requirements) is named by at least
// one scenario.
func Test_FeatureFiles_MapEveryRequirement(t *testing.T) {
	scenarios, err := parseFeatureDir("../../features")
	require.NoError(t, err)

	err = checkFeatureMappings(scenarios, ide2418Requirements)
	require.NoError(t, err)
}

// Test_FeatureFiles_ScenarioWithoutMapsAnchorFails proves the mapping lint
// actually fails an unmapped scenario and an uncovered requirement, rather
// than silently passing everything. It exercises the same
// checkFeatureMappings function that Test_FeatureFiles_MapEveryRequirement
// uses, against fixtures that never touch the real features/ directory.
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

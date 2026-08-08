/*
 * © 2022-2026 Snyk Limited
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

package server

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// featureScenario is one `Scenario:`/`Scenario Outline:` found in a .feature
// file, together with the requirement IDs from the `# maps: <id>[, <id>...]`
// comment directly above it (empty if there is none).
type featureScenario struct {
	file     string
	title    string
	mapsToID []string
}

var (
	scenarioLineRe = regexp.MustCompile(`^(?:Scenario|Scenario Outline):\s*(.+)$`)
	mapsLineRe     = regexp.MustCompile(`^#\s*maps:\s*(.+)$`)
)

// parseFeatureDir parses every *.feature file under dir, recursing into
// subdirectories the same way godog's own loader (godog.Options.Paths) does.
func parseFeatureDir(dir string) ([]featureScenario, error) {
	var scenarios []featureScenario
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".feature") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading feature file %q: %w", path, err)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		scenarios = append(scenarios, parseFeatureScenarios(rel, content)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading feature dir %q: %w", dir, err)
	}
	return scenarios, nil
}

// parseFeatureScenarios scans the given feature file content for
// Scenario/Scenario Outline lines and the `# maps:` comment anchored
// directly above each one (the nearest line above the scenario line that
// isn't blank, an `@tag`, or a plain `#` comment).
func parseFeatureScenarios(file string, content []byte) []featureScenario {
	lines := strings.Split(string(content), "\n")

	var scenarios []featureScenario
	for i, raw := range lines {
		m := scenarioLineRe.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			continue
		}

		var ids []string
		for j := i - 1; j >= 0; j-- {
			prev := strings.TrimSpace(lines[j])
			if prev == "" || strings.HasPrefix(prev, "@") {
				continue
			}
			if mm := mapsLineRe.FindStringSubmatch(prev); mm != nil {
				ids = splitRequirementIDs(mm[1])
				break
			}
			if strings.HasPrefix(prev, "#") {
				// A plain documentation comment, not the maps anchor itself -
				// keep scanning upward for the real anchor.
				continue
			}
			// Known limitation: any other line stops the scan, including Gherkin
			// keywords such as `Background:`/`Rule:`/`Examples:` immediately above
			// a Scenario. Generalizing to every Gherkin keyword is open-ended, so
			// this is deliberately not handled - add the keyword here if it
			// becomes a real problem.
			break
		}

		scenarios = append(scenarios, featureScenario{file: file, title: m[1], mapsToID: ids})
	}
	return scenarios
}

func splitRequirementIDs(raw string) []string {
	var ids []string
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			ids = append(ids, part)
		}
	}
	return ids
}

// checkFeatureMappings reports an error listing every scenario missing a
// `# maps:` anchor, and every requiredID not named by any scenario's anchor.
// A nil/empty requiredIDs skips the coverage half of the check, so it can be
// used against fixtures that only exercise the per-scenario-anchor half.
func checkFeatureMappings(scenarios []featureScenario, requiredIDs []string) error {
	var unmapped []string
	covered := map[string]bool{}
	for _, sc := range scenarios {
		if len(sc.mapsToID) == 0 {
			unmapped = append(unmapped, fmt.Sprintf("%s: %q", sc.file, sc.title))
			continue
		}
		for _, id := range sc.mapsToID {
			covered[id] = true
		}
	}

	var missing []string
	for _, id := range requiredIDs {
		if !covered[id] {
			missing = append(missing, id)
		}
	}

	if len(unmapped) == 0 && len(missing) == 0 {
		return nil
	}

	sort.Strings(unmapped)
	sort.Strings(missing)

	var msg strings.Builder
	if len(unmapped) > 0 {
		fmt.Fprintf(&msg, "scenarios missing a `# maps: <requirement id>` anchor: %s", strings.Join(unmapped, "; "))
	}
	if len(missing) > 0 {
		if msg.Len() > 0 {
			msg.WriteString(" | ")
		}
		fmt.Fprintf(&msg, "requirements not covered by any scenario: %s", strings.Join(missing, ", "))
	}
	return fmt.Errorf("%s", msg.String())
}

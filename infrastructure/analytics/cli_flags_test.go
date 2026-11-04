/*
 * © 2025 Snyk Limited
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

package analytics

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLIFlagNames(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"nil input gives empty result", nil, []string{}},
		{"empty input gives empty result", []string{}, []string{}},
		{"boolean long flag is kept", []string{"--all-projects"}, []string{"--all-projects"}},
		{"boolean short flag is kept", []string{"-d"}, []string{"-d"}},
		{"multiple flags keep their order", []string{"--dev", "--all-projects", "-d"}, []string{"--dev", "--all-projects", "-d"}},
		{"value after equals sign is removed", []string{"--policy-path=.snyk"}, []string{"--policy-path"}},
		{"only the first equals sign splits key and value", []string{"--token=a=b=c"}, []string{"--token"}},
		{"empty value after equals sign is removed", []string{"--org="}, []string{"--org"}},
		{"value given as the next element is dropped", []string{"--org", "my-org-id"}, []string{"--org"}},
		{"value of a short flag given as the next element is dropped", []string{"-p", "hunter2"}, []string{"-p"}},
		{"value that looks like a path is dropped", []string{"--file", "/Users/jane/work/pom.xml"}, []string{"--file"}},
		{"value that looks like a url is dropped", []string{"--registry", "https://user:pw@registry.corp.example"}, []string{"--registry"}},
		{"flag followed by value followed by flag", []string{"--org", "abc", "--dev"}, []string{"--org", "--dev"}},
		{"element holding several flags is split on whitespace", []string{"--all-projects -d --org=abc secret"}, []string{"--all-projects", "-d", "--org"}},
		{"surrounding whitespace is ignored", []string{"  --dev  "}, []string{"--dev"}},
		{"empty string is dropped", []string{""}, []string{}},
		{"blank string is dropped", []string{"   "}, []string{}},
		{"positional argument alone is dropped", []string{"some-secret"}, []string{}},
		{"java style property keeps only its name", []string{"-Dmy.prop=secret"}, []string{"-Dmy.prop"}},
		{"double dash separator is kept and later flags are reduced", []string{"--all-projects", "--", "-Dpass=secret"}, []string{"--all-projects", "--", "-Dpass"}},
		{"duplicate flags are kept", []string{"--dev", "--dev"}, []string{"--dev", "--dev"}},
		{"mixed realistic input", []string{"--reachability=true", "--reachability-filter=reachable", "--org", "abc", "-d", ""}, []string{"--reachability", "--reachability-filter", "--org", "-d"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, CLIFlagNames(tt.input))
		})
	}

	t.Run("does not modify the input", func(t *testing.T) {
		input := []string{"--org=abc", "secret"}
		_ = CLIFlagNames(input)
		assert.Equal(t, []string{"--org=abc", "secret"}, input)
	})

	t.Run("serialized result contains no value", func(t *testing.T) {
		secrets := []string{"s3cr3t-value", "my-org-id", "/Users/jane", "corp.example"}
		input := []string{
			"--org=my-org-id",
			"--project-name", "s3cr3t-value",
			"--file=/Users/jane/pom.xml",
			"--registry=https://corp.example/npm",
		}

		out, err := json.Marshal(CLIFlagNames(input))

		assert.NoError(t, err)
		for _, secret := range secrets {
			assert.NotContains(t, string(out), secret)
		}
	})
}

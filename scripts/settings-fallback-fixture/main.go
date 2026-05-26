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

// ABOUTME: Fixture generator for settings-fallback.html JS tests.
// ABOUTME: Substitutes {{PLACEHOLDER}} tokens with deterministic test values.
// ABOUTME: Run with: go run scripts/settings-fallback-fixture/main.go > js-tests/fixtures/settings-fallback.html
// ABOUTME: Use --release-channel to test stable/rc/preview/custom variants.
// ABOUTME: Use --custom-version to set the custom version string (only used when --release-channel=custom).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	releaseChannel := flag.String("release-channel", "stable", "CLI release channel: stable, rc, preview, or a version like v1.1292.0")
	cliPath := flag.String("cli-path", "/usr/local/bin/snyk", "CLI path value")
	baseURL := flag.String("base-url", "https://downloads.snyk.io", "CLI download base URL")
	manageBinaries := flag.Bool("manage-binaries", true, "Whether automatic_download checkbox is checked")
	insecure := flag.Bool("insecure", false, "Whether proxy_insecure checkbox is checked")
	outputFile := flag.String("output-file", "", "Write HTML to file instead of stdout")
	flag.Parse()

	src := "shared_ide_resources/ui/html/settings-fallback.html"
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", src, err)
		os.Exit(1)
	}

	html := string(data)

	manageBinariesChecked := ""
	if *manageBinaries {
		manageBinariesChecked = "checked"
	}

	insecureChecked := ""
	if *insecure {
		insecureChecked = "checked"
	}

	knownChannels := map[string]bool{"stable": true, "rc": true, "preview": true}
	isCustom := !knownChannels[*releaseChannel]

	stableSelected, rcSelected, previewSelected, customSelected := "", "", "", ""
	customValue := ""
	customHidden := "hidden"

	if isCustom {
		customSelected = "selected"
		customValue = *releaseChannel
		customHidden = ""
	} else {
		switch *releaseChannel {
		case "stable":
			stableSelected = "selected"
		case "rc":
			rcSelected = "selected"
		case "preview":
			previewSelected = "selected"
		}
	}

	replacements := map[string]string{
		"{{MANAGE_BINARIES_CHECKED}}":        manageBinariesChecked,
		"{{CLI_BASE_DOWNLOAD_URL}}":           *baseURL,
		"{{CLI_PATH}}":                        *cliPath,
		"{{CHANNEL_STABLE_SELECTED}}":         stableSelected,
		"{{CHANNEL_RC_SELECTED}}":             rcSelected,
		"{{CHANNEL_PREVIEW_SELECTED}}":        previewSelected,
		"{{CHANNEL_CUSTOM_SELECTED}}":         customSelected,
		"{{CLI_RELEASE_CHANNEL_CUSTOM_VALUE}}": customValue,
		"{{CLI_RELEASE_CHANNEL_CUSTOM_HIDDEN}}": customHidden,
		"{{INSECURE_CHECKED}}":                insecureChecked,
	}

	for placeholder, value := range replacements {
		html = strings.ReplaceAll(html, placeholder, value)
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(html), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprint(os.Stdout, html)
	}
}

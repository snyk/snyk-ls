/*
 * © 2026 Snyk Limited
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

package fileicon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/fileicon"
)

func TestPackageManagerSVG_AllKnownKeys_ReturnSVG(t *testing.T) {
	knownKeys := []string{
		"gradle", "maven", "npm", "pip", "rubygems",
		"yarn", "yarn-workspace", "sbt", "golangdep", "govendor",
		"golang", "gomodules", "nuget", "paket", "composer",
		"linux", "deb", "apk", "cocoapods", "rpm", "dockerfile",
	}
	for _, key := range knownKeys {
		t.Run(key, func(t *testing.T) {
			svg := fileicon.PackageManagerSVG(key)
			assert.NotEmpty(t, svg, "expected SVG for key %q", key)
			assert.Contains(t, svg, "<svg", "expected <svg element for key %q", key)
		})
	}
}

func TestPackageManagerSVG_UnknownKey_ReturnsEmpty(t *testing.T) {
	assert.Empty(t, fileicon.PackageManagerSVG("unknown-pkg-manager"))
	assert.Empty(t, fileicon.PackageManagerSVG(""))
}

func TestPackageManagerSVG_CaseInsensitive(t *testing.T) {
	assert.Equal(t, fileicon.PackageManagerSVG("npm"), fileicon.PackageManagerSVG("NPM"))
	assert.Equal(t, fileicon.PackageManagerSVG("gradle"), fileicon.PackageManagerSVG("Gradle"))
	assert.Equal(t, fileicon.PackageManagerSVG("Maven"), fileicon.PackageManagerSVG("maven"))
}

func TestPackageManagerSVG_RpmIcon_Is16px(t *testing.T) {
	svg := fileicon.PackageManagerSVG("rpm")
	assert.Contains(t, svg, `width="16"`)
	assert.Contains(t, svg, `height="16"`)
}

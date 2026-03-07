/*
 * © 2025 Snyk Limited All rights reserved.
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

package config

import (
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/internal/types"
)

// ConfigOption is a function that configures a Config instance
type ConfigOption func(*Config)

// WithBinarySearchPaths sets custom binary search paths
func WithBinarySearchPaths(paths []string) ConfigOption {
	return func(c *Config) {
		c.engine.GetConfiguration().Set(configuration.UserGlobalKey(types.SettingBinarySearchPaths), paths)
	}
}

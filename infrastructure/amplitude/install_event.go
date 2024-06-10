/*
 * © 2022 Snyk Limited All rights reserved.
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

package amplitude

import (
	"os"
	"path/filepath"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/ux"
)

const (
	installFilename = ".installed_event_sent"
)

func (c *Client) captureInstalledEvent() {
	installFile := filepath.Join(config.CurrentConfig().CliSettings().DefaultBinaryInstallPath(), installFilename)
	_, err := os.Stat(installFile)
	if err == nil {
		return
	}

	method := "segment.captureInstalledEvent"

	if !os.IsNotExist(err) {
		c.c.Logger().Error().Err(err).Str("method", method).Msg("Failed to verify if installation analytics have been captured.")
		c.errorReporter.CaptureError(err)
		return
	}

	f, err := os.Create(installFile)
	if err != nil {
		c.c.Logger().Error().Err(err).Str("method", method).Msg("Failed to save installation analytics state.")
		c.errorReporter.CaptureError(err)
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	c.PluginIsInstalled(ux.PluginIsInstalledProperties{})
	c.c.Logger().Info().Str("method", method).Msg("Installation event captured.")
}

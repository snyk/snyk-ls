/*
 * Copyright 2022 Snyk Ltd.
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

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/application/server/lsp"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
)

type Initializer struct {
	errorReporter error_reporting.ErrorReporter
	installer     install.Installer
}

func NewInitializer(errorReporter error_reporting.ErrorReporter, installer install.Installer) *Initializer {
	return &Initializer{
		errorReporter: errorReporter,
		installer:     installer,
	}
}

func (i *Initializer) Init() error {
	Mutex.Lock()
	defer Mutex.Unlock()

	cliInstalled := config.CurrentConfig().CliSettings().Installed()
	if !config.CurrentConfig().ManageBinariesAutomatically() {
		if !cliInstalled {
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Automatic CLI downloads are disabled and no CLI path is configured. Enable automatic downloads or set a valid CLI path."})
		}
		return nil
	}

	if cliInstalled && i.isOutdatedCli() {
		go i.updateCli()
	}

	if cliInstalled {
		return nil
	}

	for attempt := 0; !config.CurrentConfig().CliSettings().Installed(); attempt++ {
		if attempt > 2 {
			config.CurrentConfig().SetSnykIacEnabled(false)
			config.CurrentConfig().SetSnykOssEnabled(false)
			log.Warn().Str("method", "cli.Init").Msg("Disabling Snyk OSS and Snyk Iac as no CLI found after 3 tries")
			break
		}
		i.installCli()
		if !config.CurrentConfig().CliSettings().Installed() {
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

func (i *Initializer) installCli() {
	var err error
	var cliPath string
	currentConfig := config.CurrentConfig()
	if currentConfig.CliSettings().IsPathDefined() {
		cliPath = currentConfig.CliSettings().Path()
	} else {
		cliPath, err = i.installer.Find()
		if err != nil {
			log.Info().Str("method", "installCli").Msg("could not find Snyk CLI in user directories and PATH.")
			cliFileName := (&install.Discovery{}).ExecutableName(false)
			cliPath = filepath.Join(currentConfig.CliSettings().DefaultBinaryInstallPath(), cliFileName)
		} else {
			log.Info().Str("method", "installCli").Msgf("found CLI at %s", cliPath)
		}
		currentConfig.CliSettings().SetPath(cliPath)
	}

	// Check if the file is actually in the cliPath
	if !currentConfig.CliSettings().Installed() {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI will be downloaded to run security scans."})
		cliPath, err = i.installer.Install(context.Background())
		notification.Send(lsp.SnykIsAvailableCli{CliPath: cliPath})
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			i.handleInstallerError(err)
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Failed to download Snyk CLI."})
			cliPath, _ = i.installer.Find()
		} else {
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI has been downloaded."})
		}
	}

	if cliPath != "" {
		notification.Send(lsp.SnykIsAvailableCli{CliPath: cliPath})
		log.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
	} else {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Could not find, nor install Snyk CLI"})
	}
}

func (i *Initializer) handleInstallerError(err error) {
	// we don't want to report errors caused by concurrent downloads, they will resolve themselves after 1h
	if !strings.Contains(err.Error(), "installer lockfile from ") {
		i.errorReporter.CaptureError(err)
	}
}

func (i *Initializer) updateCli() {
	Mutex.Lock()
	defer Mutex.Unlock()

	updated, err := i.installer.Update(context.Background())
	if err != nil {
		log.Err(err).Str("method", "updateCli").Msg("Failed to update CLI")
		i.handleInstallerError(err)
	}

	if updated {
		log.Info().Str("method", "updateCli").Msg("CLI updated.")
	} else {
		log.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func (i *Initializer) isOutdatedCli() bool {
	cliPath := config.CurrentConfig().CliSettings().Path()

	fileInfo, err := os.Stat(cliPath) // todo: we can save stat calls by caching mod time
	if err != nil {
		log.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

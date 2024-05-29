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

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	noti "github.com/snyk/snyk-ls/domain/ide/notification"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/lsp"
)

type Initializer struct {
	errorReporter error_reporting.ErrorReporter
	installer     install.Installer
	notifier      noti.Notifier
	cli           Executor
}

func NewInitializer(errorReporter error_reporting.ErrorReporter,
	installer install.Installer,
	notifier noti.Notifier,
	cli Executor,
) *Initializer {
	i := &Initializer{
		errorReporter: errorReporter,
		installer:     installer,
		notifier:      notifier,
		cli:           cli,
	}
	settings := config.CurrentConfig().CliSettings()
	if settings.Installed() {
		i.logCliVersion(settings.Path())
	}
	return i
}

func (i *Initializer) Init() error {
	Mutex.Lock()
	defer Mutex.Unlock()

	logger := log.With().Str("method", "cli.Init").Logger()
	c := config.CurrentConfig()
	cliSettings := c.CliSettings()
	cliInstalled := cliSettings.Installed()
	logger.Debug().Str("cliPath", cliPathInConfig()).Msgf("CLI installed: %v", cliInstalled)
	if !c.ManageCliBinariesAutomatically() {
		if !cliSettings.IsPathDefined() {
			i.notifier.SendShowMessage(sglsp.Warning,
				"Automatic CLI downloads are disabled and no CLI path is configured. Enable automatic downloads or set a valid CLI path.")
			return errors.New("automatic management of binaries is disabled, and CLI is not found")
		}
		return nil
	}

	if cliInstalled {
		if i.isOutdatedCli() {
			go i.updateCli()
		}
		i.notifier.Send(lsp.SnykIsAvailableCli{CliPath: cliPathInConfig()})
		return nil
	}

	// When the CLI is not installed, try to install it
	for attempt := 0; !c.CliSettings().Installed(); attempt++ {
		if attempt > 2 {
			c.SetSnykIacEnabled(false)
			c.SetSnykOssEnabled(false)
			log.Warn().Str("method", "cli.Init").Msg("Disabling Snyk OSS and Snyk Iac as no CLI found after 3 tries")

			return errors.New("could not find or download CLI")
		}
		i.installCli()
		if !c.CliSettings().Installed() {
			log.Debug().Str("method", "cli.Init").Msg("CLI not found, retrying in 2s")
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
		cliPath = cliPathInConfig()
		log.Info().Str("method", "installCli").Str("cliPath", cliPath).Msg("Using configured CLI path")
	} else {
		cliFileName := (&install.Discovery{}).ExecutableName(false)
		cliPath = filepath.Join(currentConfig.CliSettings().DefaultBinaryInstallPath(), cliFileName)
		currentConfig.CliSettings().SetPath(cliPath)
	}

	// Check if the file is actually in the cliPath
	if !currentConfig.CliSettings().Installed() {
		i.notifier.SendShowMessage(sglsp.Info, "Snyk CLI will be downloaded to run security scans.")
		cliPath, err = i.installer.Install(context.Background())
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			i.handleInstallerError(err)
			i.notifier.SendShowMessage(sglsp.Warning, "Failed to download Snyk CLI.")
			cliPath, _ = i.installer.Find()
		} else {
			i.notifier.SendShowMessage(sglsp.Info, "Snyk CLI has been downloaded.")
			i.logCliVersion(cliPath)
		}
	} else {
		// If the file is in the cliPath, log the current version
		i.logCliVersion(cliPath)
	}

	if cliPath != "" {
		i.notifier.Send(lsp.SnykIsAvailableCli{CliPath: cliPath})
		log.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
	} else {
		i.notifier.SendShowMessage(sglsp.Warning, "Could not find, nor install Snyk CLI")
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
		i.logCliVersion(cliPathInConfig())
	} else {
		log.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func (i *Initializer) isOutdatedCli() bool {
	cliPath := cliPathInConfig()

	fileInfo, err := os.Stat(cliPath)
	if err != nil {
		log.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

// logCliVersion runs the cli with `--version` and returns the version
func (i *Initializer) logCliVersion(cliPath string) {
	output, err := i.cli.Execute(context.Background(), []string{cliPath, "--version"}, "")
	version := "unknown version"
	if err == nil && len(output) > 0 {
		version = string(output)
		version = strings.Trim(version, "\n")
	}
	log.Info().Msg("snyk-cli: " + version + " (" + cliPath + ")")
}

// cliPath is a single source of truth for the CLI path
func cliPathInConfig() string { return config.CurrentConfig().CliSettings().Path() }

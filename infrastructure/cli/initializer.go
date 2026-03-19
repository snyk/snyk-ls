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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	noti "github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/internal/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/types"
)

type Initializer struct {
	errorReporter  error_reporting.ErrorReporter
	installer      install.Installer
	notifier       noti.Notifier
	cli            Executor
	conf           configuration.Configuration
	configResolver types.ConfigResolverInterface
	logger         *zerolog.Logger
}

func NewInitializer(conf configuration.Configuration, logger *zerolog.Logger, errorReporter error_reporting.ErrorReporter,
	installer install.Installer,
	notifier noti.Notifier,
	cli Executor,
	configResolver types.ConfigResolverInterface,
) *Initializer {
	i := &Initializer{
		errorReporter:  errorReporter,
		installer:      installer,
		notifier:       notifier,
		cli:            cli,
		conf:           conf,
		configResolver: configResolver,
		logger:         logger,
	}
	return i
}

func (i *Initializer) Init(ctx context.Context) error {
	Mutex.Lock()
	defer Mutex.Unlock()

	logger := i.logger.With().Str("method", "cli.Init").Logger()
	cliInstalled := config.CliInstalled(i.conf)
	if !config.ManageCliBinariesAutomatically(i.conf) {
		if i.configResolver.GetString(types.SettingCliPath, nil) == "" {
			i.notifier.SendShowMessage(sglsp.Warning,
				"Automatic CLI downloads are disabled and no CLI path is configured. Enable automatic downloads or set a valid CLI path.")
			return errors.New("automatic management of binaries is disabled, and CLI is not found")
		}
		return nil
	}

	// wait for being online
	for i.configResolver.GetBool(types.SettingOffline, nil) {
		time.Sleep(2 * time.Second)
	}

	if cliInstalled {
		if i.isOutdatedCli() {
			go i.updateCli(ctx)
		}
		i.notifier.Send(types.SnykIsAvailableCli{CliPath: i.cliPathInConfig()})
		return nil
	}

	// When the CLI is not installed, try to install it
	for attempt := 0; !config.CliInstalled(i.conf); attempt++ {
		if attempt > 2 && !i.configResolver.GetBool(types.SettingOffline, nil) {
			i.conf.Set(configresolver.UserGlobalKey(types.SettingSnykIacEnabled), false)
			i.conf.Set(configresolver.UserGlobalKey(types.SettingSnykOssEnabled), false)
			logger.Warn().Str("method", "cli.Init").Msg("Disabling Snyk OSS and Snyk Iac as no CLI found after 3 tries")

			return errors.New("could not find or download CLI")
		}
		i.installCli(ctx)
		if !config.CliInstalled(i.conf) {
			logger.Debug().Str("method", "cli.Init").Msg("CLI not found, retrying in 2s")
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

func (i *Initializer) installCli(ctx context.Context) {
	var err error
	var cliPath string
	if i.configResolver.GetString(types.SettingCliPath, nil) != "" {
		cliPath = i.cliPathInConfig()
		i.logger.Info().Str("method", "installCli").Str("cliPath", cliPath).Msg("Using configured CLI path")
	} else {
		cliFileName := (&install.Discovery{}).ExecutableName(false)
		cliPath = filepath.Join(config.CliDefaultBinaryInstallPath(), cliFileName)
		i.conf.Set(configresolver.UserGlobalKey(types.SettingCliPath), cliPath)
	}

	// Check if the file is actually in the cliPath
	if !config.CliInstalled(i.conf) {
		i.notifier.SendShowMessage(sglsp.Info, "Snyk CLI will be downloaded to run security scans.")
		cliPath, err = i.installer.Install(ctx)
		if err != nil {
			i.logger.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			i.handleInstallerError(err)
			i.notifier.SendShowMessage(sglsp.Warning, "Failed to download Snyk CLI.")
			cliPath, _ = i.installer.Find()
		} else {
			i.notifier.SendShowMessage(sglsp.Info, "Snyk CLI has been downloaded.")
			go i.logCliVersion(ctx, cliPath)
		}
	} else {
		// If the file is in the cliPath, log the current version
		go i.logCliVersion(ctx, cliPath)
	}

	if cliPath != "" {
		i.notifier.Send(types.SnykIsAvailableCli{CliPath: cliPath})
		i.logger.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
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

func (i *Initializer) updateCli(ctx context.Context) {
	Mutex.Lock()
	defer Mutex.Unlock()
	updated, err := i.installer.Update(ctx)
	if err != nil {
		i.logger.Err(err).Str("method", "updateCli").Msg("Failed to update CLI")
		i.handleInstallerError(err)
	}

	if updated {
		i.logger.Info().Str("method", "updateCli").Msg("CLI updated.")
		go i.logCliVersion(ctx, i.cliPathInConfig())
	} else {
		go i.logger.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func (i *Initializer) isOutdatedCli() bool {
	cliPath := i.cliPathInConfig()

	fileInfo, err := os.Stat(cliPath)
	if err != nil {
		i.logger.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

// logCliVersion runs the cli with `--version` and returns the version
func (i *Initializer) logCliVersion(ctx context.Context, cliPath string) {
	output, err := i.cli.Execute(ctx, []string{cliPath, "--version"}, "", nil)
	version := "unknown version"
	if err == nil && len(output) > 0 {
		version = string(output)
		version = strings.Trim(version, "\n")
	}
	i.logger.Info().Msg("snyk-cli: " + version + " (" + cliPath + ")")
}

// cliPathInConfig returns the CLI path from GAF configuration (cleaned).
func (i *Initializer) cliPathInConfig() string {
	p := i.configResolver.GetString(types.SettingCliPath, nil)
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
}

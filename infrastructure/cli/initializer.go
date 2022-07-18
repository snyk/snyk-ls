package cli

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/infrastructure/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
	"github.com/snyk/snyk-ls/presentation/lsp"
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

func (i *Initializer) Init() {
	Mutex.Lock()
	defer Mutex.Unlock()

	cliInstalled := config.CurrentConfig().CliSettings().Installed()
	if !config.CurrentConfig().ManageBinariesAutomatically() {
		if !cliInstalled {
			notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Automatic CLI downloads are disabled and no CLI path is configured. Enable automatic downloads or set a valid CLI path."})
		}
		return
	}

	if cliInstalled && i.isOutdatedCli() {
		go i.updateCli()
	}

	if cliInstalled {
		return
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
}

func (i *Initializer) installCli() {
	var err error
	var cliPath string
	if config.CurrentConfig().CliSettings().IsPathDefined() {
		cliPath = config.CurrentConfig().CliSettings().Path()
	} else {
		cliPath, err = i.installer.Find()
		if err != nil {
			log.Info().Str("method", "installCli").Msg("could not find Snyk CLI in user directories and PATH.")
		}
	}

	if cliPath == "" {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI needs to be installed."})

		cliPath, err = i.installer.Install(context.Background())
		notification.Send(lsp.CliDownloadedParams{CliPath: cliPath})
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			i.handleInstallerError(err)
			cliPath, _ = i.installer.Find()
		}
	}

	if cliPath != "" {
		config.CurrentConfig().CliSettings().SetPath(cliPath)
		notification.Send(lsp.CliDownloadedParams{CliPath: cliPath})
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

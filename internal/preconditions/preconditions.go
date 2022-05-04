package preconditions

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
)

func EnsureReadyForAnalysisAndWait() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()
	cliInstalled := environment.CliInstalled()
	authenticated := environment.Authenticated()
	if cliInstalled && authenticated {
		return
	}

	for !environment.CliInstalled() {
		installCli()
		time.Sleep(2 * time.Second)
	}

	// if outdated, update
	if isOutdatedCli() {
		go updateCli()
	}

	if !authenticated {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})
		auth.Authenticate()
	}
}

func installCli() {
	i := install.NewInstaller()
	cliPath, err := i.Find()
	if err != nil {
		log.Info().Str("method", "installCli").Msg("could not find Snyk CLI in user directories and PATH.")
	}

	if cliPath == "" {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI needs to be installed."})

		cliPath, err = i.Install(context.Background())
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			error_reporting.CaptureError(err)
			cliPath, _ = i.Find()
		}
	}

	if cliPath != "" {
		err := environment.SetCliPath(cliPath)
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("Couldn't update environment with Snyk cli path")
		}
		log.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
	} else {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Could not find, nor install Snyk CLI"})
	}
}

func updateCli() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()

	i := install.NewInstaller()
	updated, err := i.Update(context.Background())
	if err != nil {
		log.Err(err).Str("method", "updateCli").Msg("Failed to update CLI")
		error_reporting.CaptureError(err)
	}

	if updated {
		log.Info().Str("method", "updateCli").Msg("CLI updated.")
	} else {
		log.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func isOutdatedCli() bool {
	cliPath := environment.CliPath()

	fileInfo, err := os.Stat(cliPath) // todo: we can save stat calls by caching mod time
	if err != nil {
		log.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

package preconditions

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/cli/install"
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

	if !authenticated {
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
	}
}

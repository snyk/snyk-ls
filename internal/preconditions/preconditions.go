package preconditions

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config"
	"github.com/snyk/snyk-ls/di"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
)

func EnsureReadyForAnalysisAndWait(ctx context.Context) {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()

	// lock all CLI executions
	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()

	cliInstalled := config.CurrentConfig().CliInstalled()
	authenticated := config.CurrentConfig().Authenticated()

	if cliInstalled && isOutdatedCli() {
		go updateCli()
	}

	if cliInstalled && authenticated {
		return
	}

	for i := 0; !config.CurrentConfig().CliInstalled(); i++ {
		if i > 2 {
			config.CurrentConfig().SetSnykIacEnabled(false)
			config.CurrentConfig().SetSnykOssEnabled(false)
			log.Warn().Str("method", "EnsureReadyForAnalysisAndWait").Msg("Disabling Snyk OSS and Snyk Iac as no CLI found after 3 tries")
			break
		}
		installCli(ctx)
		time.Sleep(2 * time.Second)
	}

	if !authenticated {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})
		auth.Authenticate(ctx)
	}
}

func installCli(ctx context.Context) {
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
			handleInstallerError(err)
			cliPath, _ = i.Find()
		}
	}

	if cliPath != "" {
		err := config.CurrentConfig().SetCliPath(cliPath)
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("Couldn't update config.CurrentConfig() with Snyk cli path")
		}
		log.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
	} else {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Could not find, nor install Snyk CLI"})
	}
}

func handleInstallerError(err error) {
	// we don't want to report errors caused by concurrent downloads, they will resolve themselves after 1h
	if !strings.Contains(err.Error(), "installer lockfile from ") {
		di.ErrorReporter().CaptureError(err)
	}
}

func updateCli() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()

	i := install.NewInstaller()
	updated, err := i.Update(context.Background())
	if err != nil {
		log.Err(err).Str("method", "updateCli").Msg("Failed to update CLI")
		handleInstallerError(err)
	}

	if updated {
		log.Info().Str("method", "updateCli").Msg("CLI updated.")
	} else {
		log.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func isOutdatedCli() bool {
	cliPath := config.CurrentConfig().CliPath()

	fileInfo, err := os.Stat(cliPath) // todo: we can save stat calls by caching mod time
	if err != nil {
		log.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

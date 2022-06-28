package preconditions

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/error_reporting"
	"github.com/snyk/snyk-ls/internal/cli"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
)

type EnvironmentInitializer struct {
	authenticator *auth.Authenticator
	errorReporter error_reporting.ErrorReporter
}

func New(authenticator *auth.Authenticator, errorReporter error_reporting.ErrorReporter) *EnvironmentInitializer {
	return &EnvironmentInitializer{
		authenticator: authenticator,
		errorReporter: errorReporter,
	}
}

func (e *EnvironmentInitializer) WaitUntilCLIAndAuthReady(ctx context.Context) {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()

	// lock all CLI executions
	cli.Mutex.Lock()
	defer cli.Mutex.Unlock()

	cliInstalled := config.CurrentConfig().CliInstalled()
	authenticated := config.CurrentConfig().Authenticated()

	if cliInstalled && e.isOutdatedCli() {
		go e.updateCli()
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
		e.installCli()
		time.Sleep(2 * time.Second)
	}

	if !authenticated {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})
		e.authenticator.Authenticate(ctx)
	}
}

func (e *EnvironmentInitializer) installCli() {
	i := install.NewInstaller(e.errorReporter)
	cliPath, err := i.Find()
	if err != nil {
		log.Info().Str("method", "installCli").Msg("could not find Snyk CLI in user directories and PATH.")
	}

	if cliPath == "" {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI needs to be installed."})

		cliPath, err = i.Install(context.Background())
		if err != nil {
			log.Err(err).Str("method", "installCli").Msg("could not download Snyk CLI binary")
			e.handleInstallerError(err)
			cliPath, _ = i.Find()
		}
	}

	if cliPath != "" {
		config.CurrentConfig().SetCliPath(cliPath)
		log.Info().Str("method", "installCli").Str("snyk", cliPath).Msg("Snyk CLI found.")
	} else {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Could not find, nor install Snyk CLI"})
	}
}

func (e *EnvironmentInitializer) handleInstallerError(err error) {
	// we don't want to report errors caused by concurrent downloads, they will resolve themselves after 1h
	if !strings.Contains(err.Error(), "installer lockfile from ") {
		e.errorReporter.CaptureError(err)
	}
}

func (e *EnvironmentInitializer) updateCli() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()

	i := install.NewInstaller(e.errorReporter)
	updated, err := i.Update(context.Background())
	if err != nil {
		log.Err(err).Str("method", "updateCli").Msg("Failed to update CLI")
		e.handleInstallerError(err)
	}

	if updated {
		log.Info().Str("method", "updateCli").Msg("CLI updated.")
	} else {
		log.Info().Str("method", "updateCli").Msg("CLI is latest.")
	}
}

func (e *EnvironmentInitializer) isOutdatedCli() bool {
	cliPath := config.CurrentConfig().CliPath()

	fileInfo, err := os.Stat(cliPath) // todo: we can save stat calls by caching mod time
	if err != nil {
		log.Err(err).Str("method", "isOutdatedCli").Msg("Failed to stat CLI file.")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

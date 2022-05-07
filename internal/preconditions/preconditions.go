package preconditions

import (
	"context"
	"os"
	"time"

	sglsp "github.com/sourcegraph/go-lsp"

	"github.com/snyk/snyk-ls/config/environment"
	"github.com/snyk/snyk-ls/error_reporting"
	"github.com/snyk/snyk-ls/internal/cli/auth"
	"github.com/snyk/snyk-ls/internal/cli/install"
	"github.com/snyk/snyk-ls/internal/notification"
)

var logger = environment.Logger

func EnsureReadyForAnalysisAndWait() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()
	cliInstalled := environment.CliInstalled()
	authenticated := environment.Authenticated()

	if cliInstalled && isOutdatedCli() {
		go updateCli()
	}

	if cliInstalled && authenticated {
		return
	}

	for !environment.CliInstalled() {
		installCli()
		time.Sleep(2 * time.Second)
	}

	if !authenticated {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Authenticating to Snyk. This could open a browser window."})
		auth.Authenticate()
	}
}

func installCli() {
	i := install.NewInstaller()
	cliPath, err := i.Find()
	ctx := context.Background()
	if err != nil {
		logger.
			WithField("method", "installCli").
			Info(ctx, "could not find Snyk CLI in user directories and PATH")
	}

	if cliPath == "" {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Info, Message: "Snyk CLI needs to be installed."})

		cliPath, err = i.Install(ctx)
		if err != nil {
			logger.
				WithField("method", "installCli").
				WithError(err).
				Error(ctx, "could not download Snyk CLI binary")
			error_reporting.CaptureError(err)
			cliPath, _ = i.Find()
		}
	}

	if cliPath != "" {
		err := environment.SetCliPath(cliPath)
		if err != nil {
			logger.
				WithField("method", "installCli").
				WithError(err).
				Error(ctx, "Couldn't update environment with Snyk cli path")
		}
		logger.
			WithField("method", "installCli").
			WithField("snyk", cliPath).
			Info(ctx, "Snyk CLI found")
	} else {
		notification.Send(sglsp.ShowMessageParams{Type: sglsp.Warning, Message: "Could not find, nor install Snyk CLI"})
	}
}

func updateCli() {
	install.Mutex.Lock()
	defer install.Mutex.Unlock()
	ctx := context.Background()

	i := install.NewInstaller()
	updated, err := i.Update(ctx)
	if err != nil {
		logger.
			WithField("method", "updateCli").
			WithError(err).
			Error(ctx, "Failed to update CLI")
		error_reporting.CaptureError(err)
	}

	if updated {
		logger.WithField("method", "updateCli").Info(ctx, "CLI updated")
	} else {
		logger.WithField("method", "updateCli").Info(ctx, "CLI is already latest")
	}
}

func isOutdatedCli() bool {
	cliPath := environment.CliPath()

	fileInfo, err := os.Stat(cliPath) // todo: we can save stat calls by caching mod time
	if err != nil {
		logger.
			WithField("method", "isOutdatedCli").
			WithError(err).
			Error(context.Background(), "Failed to stat CLI file")
		return false
	}

	fourDaysAgo := time.Now().Add(-time.Hour * 24 * 4)

	return fileInfo.ModTime().Before(fourDaysAgo)
}

package segment

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/domain/observability/ux"
)

const (
	installFilename = ".installed_event_sent"
)

func (s *Client) captureInstalledEvent() {
	installFile := filepath.Join(config.CurrentConfig().DefaultBinaryInstallPath(), installFilename)
	_, err := os.Stat(installFile)
	if err == nil {
		return
	}

	method := "segment.captureInstalledEvent"

	if !os.IsNotExist(err) {
		log.Error().Err(err).Str("method", method).Msg("Failed to verify if installation analytics have been captured.")
		s.errorReporter.CaptureError(err)
		return
	}

	f, err := os.Create(installFile)
	if err != nil {
		log.Error().Err(err).Str("method", method).Msg("Failed to save installation analytics state.")
		s.errorReporter.CaptureError(err)
		return
	}
	defer f.Close()

	s.PluginIsInstalled(ux.PluginIsInstalledProperties{})
	log.Info().Str("method", method).Msg("Installation event captured.")
}

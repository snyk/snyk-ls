package util

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
)

var _ ui.UserInterface = (*LsUserInterface)(nil)

type LsUserInterface struct {
	logger *zerolog.Logger
}

func (l LsUserInterface) SelectOptions(_ string, _ []string) (int, string, error) {
	return 0, "", nil
}

func NewLsUserInterface(logger *zerolog.Logger) *LsUserInterface {
	return &LsUserInterface{
		logger: logger,
	}
}

func (l LsUserInterface) Output(output string) error {
	l.logger.Info().Msg(output)
	return nil
}

func (l LsUserInterface) OutputError(err error, _ ...ui.Opts) error {
	l.logger.Error().Err(err).Msg("received errors")
	return nil

}

func (l LsUserInterface) NewProgressBar() ui.ProgressBar {
	return nil
}

func (l LsUserInterface) Input(_ string) (string, error) {
	return "", nil
}

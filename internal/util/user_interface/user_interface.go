package user_interface

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
)

var _ ui.UserInterface = (*LsUserInterface)(nil)

type LsUserInterfaceOption func(*LsUserInterface)

type LsUserInterface struct {
	logger *zerolog.Logger
}

func WithLogger(logger *zerolog.Logger) LsUserInterfaceOption {
	return func(l *LsUserInterface) {
		l.logger = logger
	}
}

func (l LsUserInterface) SelectOptions(_ string, _ []string) (int, string, error) {
	return 0, "", nil
}

func NewLsUserInterface(opts ...LsUserInterfaceOption) *LsUserInterface {
	ui := &LsUserInterface{}
	if opts == nil {
		return ui
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(ui)
	}
	return ui
}

func (l LsUserInterface) Output(output string) error {
	if l.logger == nil {
		return nil
	}
	l.logger.Info().Msg(output)
	return nil
}

func (l LsUserInterface) OutputError(err error, _ ...ui.Opts) error {
	if l.logger == nil {
		return nil
	}
	l.logger.Error().Err(err).Msg("received errors")
	return nil
}

func (l LsUserInterface) NewProgressBar() ui.ProgressBar {
	return nil
}

func (l LsUserInterface) Input(_ string) (string, error) {
	return "", nil
}

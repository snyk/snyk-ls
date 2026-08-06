/*
 * © 2025 Snyk Limited All rights reserved.
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

// Package user_interface implements the user interface functionality
package user_interface

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui"
)

var _ ui.UserInterface = (*LsUserInterface)(nil)

type LsUserInterfaceOption func(*LsUserInterface)

type LsUserInterface struct {
	logger         *zerolog.Logger
	newProgressBar func() ui.ProgressBar
}

// WithProgressBarFactory installs a factory rather than a single bar: a bar is
// spent once cleared, so a shared one would leave every progress operation
// after the first invisible.
func WithProgressBarFactory(factory func() ui.ProgressBar) LsUserInterfaceOption {
	return func(l *LsUserInterface) {
		l.newProgressBar = factory
	}
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
	lsUi := &LsUserInterface{}
	if opts == nil {
		return lsUi
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(lsUi)
	}
	return lsUi
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
	if l.newProgressBar == nil {
		return nil
	}
	return l.newProgressBar()
}

func (l LsUserInterface) Input(_ string) (string, error) {
	return "", nil
}

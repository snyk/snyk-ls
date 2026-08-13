package user_interface

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/ui/uitypes"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/progress"
)

func TestNewLsUserInterfaceWithOptions_appliesLogger(t *testing.T) {
	logger := zerolog.Nop()
	ui := NewLsUserInterface(WithLogger(&logger))
	assert.Same(t, &logger, ui.logger)
}

func TestNewLsUserInterfaceWithOptions_ignoresNilOption(t *testing.T) {
	ui := NewLsUserInterface(nil)
	assert.Nil(t, ui.logger)
}

func TestNewProgressBar_returnsAFreshBarPerCall(t *testing.T) {
	logger := zerolog.Nop()
	tracker := progress.NewTracker(&logger)
	lsUi := NewLsUserInterface(WithProgressBarFactory(func() uitypes.ProgressBar { return tracker.New(false) }))

	first, second := lsUi.NewProgressBar(), lsUi.NewProgressBar()

	assert.NotSame(t, first, second)
}

func TestNewProgressBar_withoutFactory(t *testing.T) {
	assert.Nil(t, NewLsUserInterface().NewProgressBar())
}

package user_interface

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
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

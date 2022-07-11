package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_configGetAPICmd(t *testing.T) {
	ctx := context.Background()

	configGetAPICmd, err := configGetAPICmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"config", "get", "api"}, configGetAPICmd)
}

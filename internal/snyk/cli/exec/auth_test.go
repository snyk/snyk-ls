package exec

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuth_authCmd(t *testing.T) {
	ctx := context.Background()

	authCmd, err := authCmd(ctx)

	assert.NoError(t, err)
	assertCmd(t, []string{"auth"}, authCmd)
}

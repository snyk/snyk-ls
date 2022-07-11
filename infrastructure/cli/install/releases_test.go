package install

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestGetLatestRelease_downloadURLShouldBeNotEmpty(t *testing.T) {
	testutil.IntegTest(t)

	r := NewCLIRelease()
	ctx := context.Background()

	release, err := r.GetLatestRelease(ctx)

	assert.NoError(t, err)
	assert.NotEmpty(t, release.Assets.Linux.URL)
}

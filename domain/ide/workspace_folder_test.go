package ide

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/snyk-ls/internal/testutil"
)

func TestAddBundleHashToWorkspaceFolder(t *testing.T) {
	testutil.UnitTest(t)
	folder := NewWorkspaceFolder("testPath/a.txt", "testFolder")
	key := "bundleHash"
	value := "testHash"

	folder.AddProductAttribute(SnykCode, key, value)

	assert.Equal(t, value, folder.GetProductAttribute(SnykCode, key))
}

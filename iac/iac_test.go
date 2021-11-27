package iac

import (
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"testing"
)

func Test_snyk(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	diagnostics, _ := snyk(path)
	assert.NotEqual(t, 0, len(diagnostics))
}

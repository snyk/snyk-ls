package iac

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func Test_fetch_shouldProvideDiagnostics(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	diagnostics, _, _ := fetch(path)
	assert.NotEqual(t, 0, len(diagnostics))
}

func Test_fetch_shouldProvideCodeLenses(t *testing.T) {
	path, _ := filepath.Abs("testdata/RBAC.yaml")
	_, codeLenses, _ := fetch(path)
	assert.NotEqual(t, 0, len(codeLenses))
}

func Test_convertCodeLenses_shouldOneCodeLensPerIssue(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/RBAC-iac-result.json")

	var iacResult testResult
	json.Unmarshal(bytes, &iacResult)
	assert.NotNil(t, iacResult)
	assert.True(t, len(iacResult.IacIssues) > 0)

	actual := convertCodeLenses(iacResult)

	assert.Equal(t, len(iacResult.IacIssues), len(actual))
}

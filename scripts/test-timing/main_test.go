package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSummarizeGoTestJSONReportsPackageAndSlowTests(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/application/config","Test":"TestFast","Elapsed":0.12}`,
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/application/server","Test":"TestSlow","Elapsed":2.5}`,
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/application/config","Elapsed":1.23}`,
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/application/server","Elapsed":3.45}`,
	}, "\n"))

	summary, err := summarizeGoTestJSON(input, 2)

	require.NoError(t, err)
	require.Contains(t, summary, "Package durations")
	require.Contains(t, summary, "github.com/snyk/snyk-ls/application/server 3.450s")
	require.Contains(t, summary, "github.com/snyk/snyk-ls/application/config 1.230s")
	require.Contains(t, summary, "Slowest tests")
	require.Contains(t, summary, "github.com/snyk/snyk-ls/application/server TestSlow 2.500s")
	require.Contains(t, summary, "github.com/snyk/snyk-ls/application/config TestFast 0.120s")
}

func TestSummarizeGoTestJSONHandlesLargeOutputEvent(t *testing.T) {
	largeOutput := strings.Repeat("x", 70*1024)
	input := strings.NewReader(strings.Join([]string{
		`{"Action":"output","Package":"github.com/snyk/snyk-ls/scripts/test-timing","Output":"` + largeOutput + `"}`,
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/scripts/test-timing","Test":"TestAfterLargeOutput","Elapsed":0.42}`,
		`{"Action":"pass","Package":"github.com/snyk/snyk-ls/scripts/test-timing","Elapsed":1.5}`,
	}, "\n"))

	summary, err := summarizeGoTestJSON(input, 1)

	require.NoError(t, err)
	require.Contains(t, summary, "github.com/snyk/snyk-ls/scripts/test-timing 1.500s")
	require.Contains(t, summary, "github.com/snyk/snyk-ls/scripts/test-timing TestAfterLargeOutput 0.420s")
}

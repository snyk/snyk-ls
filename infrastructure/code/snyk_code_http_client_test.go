/*
 * © 2022-2024 Snyk Limited
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

package code

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
	"github.com/snyk/snyk-ls/internal/types"
	"github.com/snyk/snyk-ls/internal/util"
)

const (
	path1   = "Test.js"
	path2   = "Test2.js"
	content = `require('./mongoose-db');
require('./typeorm-db')

var express = require('express');
var http = require('http');
var app = express();
http.createServer(app).listen(app.get('port'), function () {
  console.log('Express server listening on port ' + app.get('port'));
});
`
	content2 = `require('./mongoose-db');
require('./typeorm-db')

var express2 = require('express');
var http = require('http');
var app = express();
http.createServer(app).listen(app.get('port'), function () {
  console.log('Express server listening on port ' + app.get('port'));
});
`
)

func clientFunc() *http.Client {
	return config.CurrentConfig().Engine().GetNetworkAccess().GetHttpClient()
}

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	s := NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(), clientFunc)
	files := map[types.FilePath]string{}
	randomAddition := fmt.Sprintf("\n public void random() { System.out.println(\"%d\") }", time.Now().UnixMicro())
	files[path1] = util.Hash([]byte(content + randomAddition))
	bundleHash, missingFiles, _ := s.CreateBundle(context.Background(), files)
	assert.NotNil(t, bundleHash)
	assert.NotEqual(t, "", bundleHash)
	assert.Equal(t, 1, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	s := NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(), clientFunc)
	var removedFiles []types.FilePath
	files := map[types.FilePath]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()

	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

	assert.Equal(t, 0, len(missingFiles))
	assert.NotEmpty(t, bundleHash)
}

func createTestExtendMap() map[types.FilePath]BundleFile {
	filesExtend := map[types.FilePath]BundleFile{}

	filesExtend[path1] = BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	filesExtend[path2] = BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	return filesExtend
}

// dummyTransport is a transport struct that always returns the response code specified in the constructor
type dummyTransport struct {
	responseCode int
	status       string
	calls        int
}

func (d *dummyTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{
		StatusCode: d.responseCode,
		Status:     d.status,
	}, nil
}

func TestSnykCodeBackendService_doCall_shouldRetry(t *testing.T) {
	c := testutil.UnitTest(t)
	d := &dummyTransport{responseCode: 502, status: "502 Bad Gateway"}
	dummyClientFunc := func() *http.Client {
		return &http.Client{
			Transport: d,
		}
	}
	s := NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(), dummyClientFunc)
	_, _, err := s.doCall(context.Background(), "GET", "https://httpstat.us/500", nil)
	assert.Error(t, err)
	assert.Equal(t, 3, d.calls)
}

func TestSnykCodeBackendService_doCall_rejected(t *testing.T) {
	c := testutil.UnitTest(t)
	dummyClientFunc := func() *http.Client {
		return &http.Client{}
	}

	s := NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(), dummyClientFunc)
	_, _, err := s.doCall(context.Background(), "GET", "https://127.0.0.1", nil)
	assert.Error(t, err)
}

func TestSnykCodeBackendService_RunAnalysisSmoke(t *testing.T) {
	c := testutil.SmokeTest(t, false)
	config.CurrentConfig().SetSnykCodeEnabled(true)

	s := NewSnykCodeHTTPClient(c, NewCodeInstrumentor(), newTestCodeErrorReporter(), clientFunc)
	shardKey := util.Hash([]byte("/"))
	var removedFiles []types.FilePath
	files := map[types.FilePath]string{}
	bytes := []byte(content)
	files[path1] = util.Hash(bytes)
	workDir := types.FilePath(t.TempDir())
	err := os.WriteFile(filepath.Join(string(workDir), path1), bytes, 0660)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(string(workDir), path2), bytes, 0660)
	require.NoError(t, err)
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()
	bundleHash, missingFiles, _ := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Len(t, missingFiles, 0, "all files should be uploaded now")

	assert.Eventually(t, func() bool {
		limitToFiles := []types.FilePath{path1, path2}

		analysisOptions := AnalysisOptions{
			bundleHash:   bundleHash,
			shardKey:     shardKey,
			limitToFiles: limitToFiles,
			severity:     0,
		}
		sarifResponse, callStatus, err := s.RunAnalysis(context.Background(), analysisOptions, workDir)
		if err != nil {
			return false
		}
		if callStatus.message == "COMPLETE" {
			// Convert SARIF response to issues to test the conversion logic
			converter := SarifConverter{sarif: sarifResponse, hoverVerbosity: c.HoverVerbosity(), logger: c.Logger()}
			issues, convErr := converter.toIssues(workDir)
			if convErr != nil {
				t.Logf("Error converting SARIF to issues: %v", convErr)
				return false
			}
			assert.Greater(t, len(issues), 0)
			return true
		}
		return false
	}, 120*time.Second, 2*time.Second)
}

// todo analysis test limit files
// todo analysis test severities

func TestGetCodeApiUrl(t *testing.T) {
	t.Run("Snykgov instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

		var snykgovInstances = []string{
			"snykgov",
			"fedramp-alpha.snykgov",
		}

		for _, instance := range snykgovInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			for _, input := range inputList {
				c := config.CurrentConfig()
				random, _ := uuid.NewRandom()
				orgUUID := random.String()

				c.UpdateApiEndpoints(input)
				c.SetOrganization(orgUUID)

				expected := "https://api." + instance + ".io/hidden/orgs/" + orgUUID + "/code"

				actual, err := GetCodeApiUrl(c)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Deeproxy instances code api url generation", func(t *testing.T) {
		t.Setenv("DEEPROXY_API_URL", "")

		var deeproxyInstances = []string{
			"snyk",
			"au.snyk",
			"dev.snyk",
		}

		for _, instance := range deeproxyInstances {
			inputList := []string{
				"https://" + instance + ".io/api/v1",
				"https://" + instance + ".io/api",
				"https://app." + instance + ".io/api",
				"https://app." + instance + ".io/api/v1",
				"https://api." + instance + ".io/api/v1",
				"https://api." + instance + ".io/v1",
				"https://api." + instance + ".io",
				"https://api." + instance + ".io?something=here",
			}

			expected := "https://deeproxy." + instance + ".io"

			for _, input := range inputList {
				c := config.CurrentConfig()
				c.UpdateApiEndpoints(input)

				actual, err := GetCodeApiUrl(c)
				assert.Nil(t, err)
				assert.Contains(t, actual, expected)
			}
		}
	})

	t.Run("Default deeprox url for code api", func(t *testing.T) {
		c := config.CurrentConfig()

		url, _ := GetCodeApiUrl(c)
		assert.Equal(t, c.SnykCodeApi(), url)
	})
}

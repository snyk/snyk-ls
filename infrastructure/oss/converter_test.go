/*
 * © 2026 Snyk Limited
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

package oss

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const threeElementArrayJSON = `[
  {
    "projectName": "proj-a",
    "packageManager": "npm",
    "path": "/tmp/a",
    "displayTargetFile": "a/package.json",
    "vulnerabilities": [
      {"id": "SNYK-A-1", "name": "pkg-a", "title": "t-a", "severity": "high"}
    ]
  },
  {
    "projectName": "proj-b",
    "packageManager": "maven",
    "path": "/tmp/b",
    "displayTargetFile": "b/pom.xml",
    "vulnerabilities": [
      {"id": "SNYK-B-1", "name": "pkg-b", "title": "t-b", "severity": "medium"},
      {"id": "SNYK-B-2", "name": "pkg-b", "title": "t-b-2", "severity": "low"}
    ]
  },
  {
    "projectName": "proj-c",
    "packageManager": "gomodules",
    "path": "/tmp/c",
    "displayTargetFile": "c/go.mod",
    "vulnerabilities": []
  }
]`

const singleObjectJSON = `{
  "projectName": "solo",
  "packageManager": "pip",
  "path": "/tmp/solo",
  "displayTargetFile": "solo/requirements.txt",
  "vulnerabilities": [
    {"id": "SNYK-SOLO-1", "name": "pkg-solo", "title": "t-solo", "severity": "critical"}
  ]
}`

func TestStreamOssJson_ArrayForm_YieldsEachElement(t *testing.T) {
	var got []scanResult
	err := StreamOssJson(strings.NewReader(threeElementArrayJSON), func(sr *scanResult) error {
		// copy out (the contract says yield must not retain *sr across calls)
		got = append(got, *sr)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, got, 3)

	assert.Equal(t, "proj-a", got[0].ProjectName)
	assert.Equal(t, "npm", got[0].PackageManager)
	assert.Equal(t, "a/package.json", got[0].DisplayTargetFile)
	require.Len(t, got[0].Vulnerabilities, 1)
	assert.Equal(t, "SNYK-A-1", got[0].Vulnerabilities[0].Id)

	assert.Equal(t, "proj-b", got[1].ProjectName)
	assert.Equal(t, "maven", got[1].PackageManager)
	require.Len(t, got[1].Vulnerabilities, 2)
	assert.Equal(t, "SNYK-B-1", got[1].Vulnerabilities[0].Id)
	assert.Equal(t, "SNYK-B-2", got[1].Vulnerabilities[1].Id)

	assert.Equal(t, "proj-c", got[2].ProjectName)
	assert.Equal(t, "gomodules", got[2].PackageManager)
	assert.Empty(t, got[2].Vulnerabilities)
}

func TestStreamOssJson_SingleObjectForm_YieldsOnce(t *testing.T) {
	calls := 0
	var got scanResult
	err := StreamOssJson(strings.NewReader(singleObjectJSON), func(sr *scanResult) error {
		calls++
		got = *sr
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "solo", got.ProjectName)
	assert.Equal(t, "pip", got.PackageManager)
	assert.Equal(t, "solo/requirements.txt", got.DisplayTargetFile)
	require.Len(t, got.Vulnerabilities, 1)
	assert.Equal(t, "SNYK-SOLO-1", got.Vulnerabilities[0].Id)
}

func TestStreamOssJson_YieldErrorShortCircuits(t *testing.T) {
	yieldErr := errors.New("stop here")
	calls := 0
	err := StreamOssJson(strings.NewReader(threeElementArrayJSON), func(sr *scanResult) error {
		calls++
		if calls == 2 {
			return yieldErr
		}
		return nil
	})
	require.ErrorIs(t, err, yieldErr)
	assert.Equal(t, 2, calls, "yield must not be invoked after returning an error")
}

func TestStreamOssJson_MalformedJSON_ReturnsError(t *testing.T) {
	truncated := `[{"projectName":"a"},`
	calls := 0
	err := StreamOssJson(strings.NewReader(truncated), func(sr *scanResult) error {
		calls++
		return nil
	})
	require.Error(t, err)
}

func TestStreamOssJson_EmptyArray_YieldsZeroTimes(t *testing.T) {
	calls := 0
	err := StreamOssJson(strings.NewReader(`[]`), func(sr *scanResult) error {
		calls++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, calls)
}

func TestStreamOssJson_ParityWithUnmarshallOssJson(t *testing.T) {
	expected, err := UnmarshallOssJson([]byte(threeElementArrayJSON))
	require.NoError(t, err)
	require.Len(t, expected, 3)

	var streamed []scanResult
	err = StreamOssJson(strings.NewReader(threeElementArrayJSON), func(sr *scanResult) error {
		streamed = append(streamed, *sr)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, streamed, len(expected))

	for i := range expected {
		assert.Equal(t, expected[i].ProjectName, streamed[i].ProjectName, "index %d", i)
		assert.Equal(t, expected[i].PackageManager, streamed[i].PackageManager, "index %d", i)
		assert.Equal(t, expected[i].Path, streamed[i].Path, "index %d", i)
		assert.Equal(t, expected[i].DisplayTargetFile, streamed[i].DisplayTargetFile, "index %d", i)
		require.Equal(t, len(expected[i].Vulnerabilities), len(streamed[i].Vulnerabilities), "index %d", i)
		if len(expected[i].Vulnerabilities) > 0 {
			assert.Equal(t, expected[i].Vulnerabilities[0].Id, streamed[i].Vulnerabilities[0].Id, "index %d", i)
		}
	}
}

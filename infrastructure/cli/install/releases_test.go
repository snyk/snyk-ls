/*
 * © 2022 Snyk Limited All rights reserved.
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

package install

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/testutil"
)

func Test_GetLatestRelease_downloadURLShouldBeNotEmpty(t *testing.T) {
	testutil.IntegTest(t)

	r := NewCLIRelease(func() *http.Client { return http.DefaultClient })

	release, err := r.GetLatestRelease()

	assert.NoError(t, err)
	assert.NotEmpty(t, release.Assets.Linux.URL)
}

func Test_getDistributionChannel(t *testing.T) {
	t.Run("stable/latest", func(t *testing.T) {
		c := testutil.UnitTest(t)
		runtimeInfo := runtimeinfo.New(
			runtimeinfo.WithName("snyk-cli"),
			runtimeinfo.WithVersion("v1.1234.4"),
		)
		c.Engine().SetRuntimeInfo(runtimeInfo)

		channel := getDistributionChannel(c)

		assert.Equal(t, "stable", channel)
	})
	t.Run("preview", func(t *testing.T) {
		c := testutil.UnitTest(t)
		runtimeInfo := runtimeinfo.New(
			runtimeinfo.WithName("snyk-cli"),
			runtimeinfo.WithVersion("v1.1234.4-preview"),
		)
		c.Engine().SetRuntimeInfo(runtimeInfo)

		channel := getDistributionChannel(c)

		assert.Equal(t, "preview", channel)
	})
	t.Run("rc", func(t *testing.T) {
		c := testutil.UnitTest(t)
		runtimeInfo := runtimeinfo.New(
			runtimeinfo.WithName("snyk-cli"),
			runtimeinfo.WithVersion("v1.1234.4-rc"),
		)
		c.Engine().SetRuntimeInfo(runtimeInfo)

		channel := getDistributionChannel(c)

		assert.Equal(t, "rc", channel)
	})
}

func Test_GetCLIDownloadURL(t *testing.T) {
	t.Run("CLI, default fallback URL", func(t *testing.T) {
		c := testutil.UnitTest(t)
		ctrl := gomock.NewController(t)
		httpClient := mocks.NewMockHTTPClient(ctrl)
		httpClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.Method == http.MethodGet
		})).Return(&http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(bytes.NewReader([]byte(`1.234`))),
		}, nil).Times(1)

		actual := GetCLIDownloadURL(c, DefaultBaseURL, httpClient)

		assert.Equal(t, "https://github.com/snyk/cli/releases", actual)
	})
	t.Run("CLI, stable, non fips", func(t *testing.T) {
		c := testutil.UnitTest(t)
		version := "v1.234"
		httpClient, name := setupCLIDownloadURLTest(t, "stable", version, c)

		actual := GetCLIDownloadURL(c, DefaultBaseURL, httpClient)

		assert.Equal(t, "https://static.snyk.io/cli/v1.234/"+name, actual)
	})
	t.Run("CLI, preview, non fips", func(t *testing.T) {
		c := testutil.UnitTest(t)
		releaseChannel := "preview"
		version := fmt.Sprintf("v1.234-%s", releaseChannel)
		httpClient, name := setupCLIDownloadURLTest(t, releaseChannel, version, c)

		actual := GetCLIDownloadURL(c, DefaultBaseURL, httpClient)

		assert.Equal(t, "https://static.snyk.io/cli/v1.234-preview/"+name, actual)
	})
}

func setupCLIDownloadURLTest(t *testing.T, releaseChannel, version string, c *config.Config) (*mocks.MockHTTPClient, string) {
	t.Helper()
	rti := runtimeinfo.New(runtimeinfo.WithVersion(version))
	c.Engine().SetRuntimeInfo(rti)
	ctrl := gomock.NewController(t)
	httpClient := mocks.NewMockHTTPClient(ctrl)
	httpClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == fmt.Sprintf("https://static.snyk.io/cli/%s/ls-protocol-version-%s", releaseChannel, config.LsProtocolVersion) &&
			req.Method == http.MethodGet
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(strings.TrimPrefix(version, "v")))),
	}, nil).Times(1)
	discovery := Discovery{}
	name := discovery.ExecutableName(false)
	return httpClient, name
}

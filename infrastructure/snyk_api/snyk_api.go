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

package snyk_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/snyk-ls/application/config"
)

type FeatureFlagType string

type SnykApiClientImpl struct {
	httpClientFunc func() *http.Client
	c              *config.Config
}
type LocalCodeEngine struct {
	AllowCloudUpload bool   `json:"allowCloudUpload"`
	Url              string `json:"url"`
	Enabled          bool   `json:"enabled"`
}
type FFResponse struct {
	Ok          bool   `json:"ok"`
	UserMessage string `json:"userMessage,omitempty"`
}

type SnykApiClient interface {
	FeatureFlagStatus(featureFlagType FeatureFlagType) (FFResponse, error)
}

type SnykApiError struct {
	msg        string
	statusCode int
}

func NewSnykApiError(msg string, statusCode int) *SnykApiError {
	return &SnykApiError{msg, statusCode}
}

func (e *SnykApiError) Error() string {
	return e.msg
}

func (e *SnykApiError) StatusCode() int {
	return e.statusCode
}

func NewSnykApiClient(c *config.Config, client func() *http.Client) SnykApiClient {
	s := SnykApiClientImpl{
		httpClientFunc: client,
		c:              c,
	}
	return &s
}

func (s *SnykApiClientImpl) addOrgToQuery(c *config.Config, u *url.URL) *url.URL {
	organization := c.Organization()
	if organization != "" {
		q := u.Query()
		q.Set("org", organization)
		u.RawQuery = q.Encode()
	}
	return u
}

func (s *SnykApiClientImpl) normalizeAPIPathForV1(c *config.Config, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(c.SnykApi(), "/v1") {
		path = "/v1" + path
	}
	return path
}

func (s *SnykApiClientImpl) FeatureFlagStatus(featureFlagType FeatureFlagType) (FFResponse, error) {
	if s.c.Offline() {
		return FFResponse{}, nil
	}
	method := "snyk_api.FeatureFlagStatus"
	c := config.CurrentConfig()
	logger := c.Logger().With().Str("method", method).Logger()

	var response FFResponse
	logger.Debug().Msgf("API: Getting %s", featureFlagType)
	path := s.normalizeAPIPathForV1(c, fmt.Sprintf("/cli-config/feature-flags/%s", string(featureFlagType)))
	u, err := url.Parse(path)
	if err != nil {
		return FFResponse{}, err
	}
	u = s.addOrgToQuery(c, u)
	logger.Debug().Str("path", path).Msg("API: Getting feature flag status")

	err = s.getApiResponse(method, u.String(), &response)
	if err != nil {
		if strings.Contains(err.Error(), "403 Forbidden") {
			logger.Debug().Msgf("Feature flag '%s' is disabled", featureFlagType)
			return FFResponse{Ok: false}, nil
		}
		logger.Err(err).Msg("Error when calling featureFlagSettings endpoint")
		return FFResponse{}, err
	}

	logger.Debug().Msgf("Feature flag '%s' is enabled", featureFlagType)
	return response, nil
}

func (s *SnykApiClientImpl) doCall(method string, endpointPath string, requestBody []byte) ([]byte, error) {
	host := s.c.SnykApi()

	b := bytes.NewBuffer(requestBody)
	req, requestErr := http.NewRequest(method, host+endpointPath, b)
	if requestErr != nil {
		return nil, NewSnykApiError(requestErr.Error(), 0)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-snyk-ide", "snyk-ls-"+config.Version)

	s.c.Logger().Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.httpClientFunc().Do(req)
	if err != nil {
		return nil, NewSnykApiError(err.Error(), 0)
	}
	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.c.Logger().Err(closeErr).Msg("Couldn't close response body in call to Snyk API")
		}
	}()

	apiError := checkResponseCode(response)
	if apiError != nil {
		return nil, apiError
	}

	responseBody, readErr := io.ReadAll(response.Body)
	s.c.Logger().Trace().Str("response.Status", response.Status).Str("responseBody",
		string(responseBody)).Msg("RECEIVED FROM REMOTE")
	if readErr != nil {
		return nil, NewSnykApiError(readErr.Error(), 0)
	}
	return responseBody, nil
}

func (s *SnykApiClientImpl) getApiResponse(caller string, path string, v interface{}) error {
	responseBody, err := s.doCall("GET", path, nil)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", caller, err, responseBody)
	}

	if err := json.Unmarshal(responseBody, v); err != nil {
		return fmt.Errorf("%s: couldn't unmarshal: %w", caller, err)
	}
	return nil
}

func checkResponseCode(r *http.Response) *SnykApiError {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}

	return NewSnykApiError("Unexpected response code: "+r.Status, r.StatusCode)
}

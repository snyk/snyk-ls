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

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
)

type FeatureFlagType string

const (
	FeatureFlagSnykCodeConsistentIgnores FeatureFlagType = "snykCodeConsistentIgnores"
)

type SnykApiClientImpl struct {
	httpClientFunc func() *http.Client
}

type LocalCodeEngine struct {
	AllowCloudUpload bool   `json:"allowCloudUpload"`
	Url              string `json:"url"`
	Enabled          bool   `json:"enabled"`
}

type SastResponse struct {
	SastEnabled                 bool            `json:"sastEnabled"`
	LocalCodeEngine             LocalCodeEngine `json:"localCodeEngine"`
	Org                         string          `json:"org"`
	SupportedLanguages          []string        `json:"supportedLanguages"`
	ReportFalsePositivesEnabled bool            `json:"reportFalsePositivesEnabled"`
	AutofixEnabled              bool            `json:"autofixEnabled"`
}

type FFResponse struct {
	Ok          bool   `json:"ok"`
	UserMessage string `json:"userMessage,omitempty"`
}

type SnykApiClient interface {
	SastSettings() (SastResponse, error)
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

func NewSnykApiClient(client func() *http.Client) SnykApiClient {
	s := SnykApiClientImpl{
		httpClientFunc: client,
	}
	return &s
}

func (s *SnykApiClientImpl) SastSettings() (SastResponse, error) {
	method := "SastSettings"
	var response SastResponse
	log.Debug().Str("method", method).Msg("API: Getting SastEnabled")
	p := "/cli-config/settings/sast"
	organization := config.CurrentConfig().Organization()
	if organization != "" {
		p += "?org=" + url.QueryEscape(organization)
	}

	err := s.processApiResponse(method, p, &response)
	if err != nil {
		log.Err(err).Str("method", method).Msg("error when calling sastEnabled endpoint")
		return SastResponse{}, err
	}
	return response, err
}

func (s *SnykApiClientImpl) FeatureFlagStatus(featureFlagType FeatureFlagType) (FFResponse, error) {
	method := "FeatureFlagStatus"
	logger := config.CurrentConfig().Logger().With().Str("method", method).Logger()

	var response FFResponse
	logger.Debug().Msgf("API: Getting %s", featureFlagType)
	path := fmt.Sprintf("/cli-config/feature-flags/%s", string(featureFlagType))
	organization := config.CurrentConfig().Organization()
	if organization != "" {
		path += "?org=" + url.QueryEscape(organization)
	}

	logger.Debug().Str("path", path).Msg("API: Getting feature flag status")

	err := s.processApiResponse(method, path, &response)
	if err != nil {
		log.Err(err).Msg("error when calling featureFlagSettings endpoint")
		return FFResponse{}, err
	}
	return response, err
}

func (s *SnykApiClientImpl) doCall(method string, endpointPath string, requestBody []byte) ([]byte, error) {
	host := config.CurrentConfig().SnykApi()
	b := bytes.NewBuffer(requestBody)
	req, requestErr := http.NewRequest(method, host+endpointPath, b)
	if requestErr != nil {
		return nil, NewSnykApiError(requestErr.Error(), 0)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-snyk-ide", "snyk-ls-"+config.Version)

	log.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.httpClientFunc().Do(req)
	if err != nil {
		return nil, NewSnykApiError(err.Error(), 0)
	}
	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			log.Err(closeErr).Msg("Couldn't close response body in call to Snyk API")
		}
	}()

	apiError := checkResponseCode(response)
	if apiError != nil {
		return nil, apiError
	}

	responseBody, readErr := io.ReadAll(response.Body)
	log.Trace().Str("response.Status", response.Status).Str("responseBody",
		string(responseBody)).Msg("RECEIVED FROM REMOTE")
	if readErr != nil {
		return nil, NewSnykApiError(readErr.Error(), 0)
	}
	return responseBody, nil
}

func (s *SnykApiClientImpl) processApiResponse(method string, path string, v interface{}) error {
	responseBody, err := s.doCall("GET", path, nil)
	if err != nil {
		return fmt.Errorf("%s: %v: %v", method, err, responseBody)
	}

	if err := json.Unmarshal(responseBody, v); err != nil {
		return fmt.Errorf("%s: couldn't unmarshal: %v", method, err)
	}
	return nil
}

func checkResponseCode(r *http.Response) *SnykApiError {
	if r.StatusCode >= 200 && r.StatusCode <= 399 {
		return nil
	}

	return NewSnykApiError("Unexpected response code: "+r.Status, r.StatusCode)
}

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

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

type FeatureFlagType string

type SnykApiClientImpl struct {
	httpClientFunc func() *http.Client
	conf           configuration.Configuration
	configResolver types.ConfigResolverInterface
	logger         *zerolog.Logger
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

func NewSnykApiClient(conf configuration.Configuration, logger *zerolog.Logger, client func() *http.Client, configResolver types.ConfigResolverInterface) SnykApiClient {
	s := SnykApiClientImpl{
		httpClientFunc: client,
		conf:           conf,
		configResolver: configResolver,
		logger:         logger,
	}
	return &s
}

func (s *SnykApiClientImpl) normalizeAPIPathForV1(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(s.configResolver.GetString(types.SettingApiEndpoint, nil), "/v1") {
		path = "/v1" + path
	}
	return path
}

func (s *SnykApiClientImpl) addOrgToQuery(u *url.URL) *url.URL {
	// Since feature flags don't have folder context, we loop through workspace folders to find the first one with a
	// configured org. Fall back to the global org if none found.
	var organization string
	ws := config.GetWorkspace(s.conf)
	if ws != nil {
		folders := ws.Folders()
		for _, folder := range folders {
			org := config.FolderOrganization(s.conf, folder.Path(), s.logger)
			if org != "" {
				organization = org
				break
			}
		}
	}
	if organization == "" {
		organization = types.GetGlobalOrganization(s.conf)
	}
	if organization != "" {
		q := u.Query()
		q.Set("org", organization)
		u.RawQuery = q.Encode()
	}
	return u
}

func (s *SnykApiClientImpl) FeatureFlagStatus(featureFlagType FeatureFlagType) (FFResponse, error) {
	if s.configResolver.GetBool(types.SettingOffline, nil) {
		return FFResponse{}, nil
	}
	method := "snyk_api.FeatureFlagStatus"
	logger := s.logger.With().Str("method", method).Logger()

	var response FFResponse
	logger.Debug().Msgf("API: Getting %s", featureFlagType)
	path := s.normalizeAPIPathForV1(fmt.Sprintf("/cli-config/feature-flags/%s", string(featureFlagType)))
	u, err := url.Parse(path)
	if err != nil {
		return FFResponse{}, err
	}
	u = s.addOrgToQuery(u)
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
	host := s.configResolver.GetString(types.SettingApiEndpoint, nil)

	b := bytes.NewBuffer(requestBody)
	req, requestErr := http.NewRequest(method, host+endpointPath, b)
	if requestErr != nil {
		return nil, NewSnykApiError(requestErr.Error(), 0)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-snyk-ide", "snyk-ls-"+config.Version)

	s.logger.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.httpClientFunc().Do(req)
	if err != nil {
		return nil, NewSnykApiError(err.Error(), 0)
	}
	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			s.logger.Err(closeErr).Msg("Couldn't close response body in call to Snyk API")
		}
	}()

	apiError := checkResponseCode(response)
	if apiError != nil {
		return nil, apiError
	}

	responseBody, readErr := io.ReadAll(response.Body)
	s.logger.Trace().Str("response.Status", response.Status).Str("responseBody",
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

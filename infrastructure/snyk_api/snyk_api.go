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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
)

type SnykApiClientImpl struct {
	httpClientFunc func() *http.Client
}

type localCodeEngine struct {
	AllowCloudUpload bool   `json:"allowCloudUpload"`
	Url              string `json:"url"`
	Enabled          bool   `json:"enabled"`
}

type SastResponse struct {
	SastEnabled                 bool            `json:"sastEnabled"`
	LocalCodeEngine             localCodeEngine `json:"localCodeEngine"`
	Org                         string          `json:"org"`
	SupportedLanguages          []string        `json:"supportedLanguages"`
	ReportFalsePositivesEnabled bool            `json:"reportFalsePositivesEnabled"`
	AutofixEnabled              bool            `json:"autofixEnabled"`
}

type activeUserResponse struct {
	Id string `json:"id"`
}

type ActiveUser struct {
	Id       string `json:"id"`
	UserName string `json:"username,omitempty"`
	Orgs     []struct {
		Name  string `json:"name,omitempty"`
		Id    string `json:"id,omitempty"`
		Group struct {
			Name string `json:"name,omitempty"`
			Id   string `json:"id,omitempty"`
		} `json:"group,omitempty"`
	} `json:"orgs,omitempty"`
}

type SnykApiClient interface {
	SastSettings() (sastResponse SastResponse, err error)
	GetActiveUser() (user ActiveUser, err error)
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
	log.Debug().Str("method", method).Msg("API: Getting SastEnabled")
	path := "/cli-config/settings/sast"
	organization := config.CurrentConfig().Organization()
	if organization != "" {
		path += "?org=" + url.QueryEscape(organization)
	}
	responseBody, err := s.doCall("GET", path, nil)
	if err != nil {
		fmtErr := fmt.Errorf("%v: %v", err, responseBody)
		log.Err(fmtErr).Str("method", method).Msg("error when calling sastEnabled endpoint")
		return SastResponse{}, err
	}

	var response SastResponse
	unmarshalErr := json.Unmarshal(responseBody, &response)
	if unmarshalErr != nil {
		fmtErr := fmt.Errorf("%v: %v", err, responseBody)
		log.Err(fmtErr).Str("method", method).Msg("couldn't unmarshal SastResponse")
		return SastResponse{}, err
	}
	log.Debug().Str("method", method).Msg("API: Done")
	return response, nil
}

func (s *SnykApiClientImpl) GetActiveUser() (ActiveUser, error) {
	log.Debug().Str("method", "GetActiveUser").Msg("API: Getting ActiveUser")
	path := "/user/me"
	responseBody, err := s.doCall("GET", path, nil)
	if err != nil {
		fmtErr := fmt.Errorf("%v: %v", err, responseBody)
		log.Err(fmtErr).Str("method", "GetActiveUser").Msg("error when calling SnykApi.GetActiveUser endpoint")
		return ActiveUser{}, NewSnykApiError(err.Error(), err.StatusCode())
	}

	var response activeUserResponse
	unmarshalErr := json.Unmarshal(responseBody, &response)
	if err != nil {
		fmtErr := fmt.Errorf("%v: %v", unmarshalErr, responseBody)
		log.Err(fmtErr).Str("method", "GetActiveUser").Msg("couldn't unmarshal GetActiveUser")
		return ActiveUser{}, NewSnykApiError(fmtErr.Error(), 0)
	}
	log.Debug().Str("method", "GetActiveUser").Msgf("Retrieved user %v", response)
	return ActiveUser{Id: response.Id}, nil
}

func (s *SnykApiClientImpl) doCall(method string,
	path string,
	requestBody []byte,
) ([]byte, *SnykApiError) {
	host := config.CurrentConfig().SnykApi()
	b := bytes.NewBuffer(requestBody)
	req, requestErr := http.NewRequest(method, host+path, b)
	if requestErr != nil {
		return nil, NewSnykApiError(requestErr.Error(), 0)
	}
	req.Header.Set("Content-Type", "application/json")
	clientID := base64.URLEncoding.EncodeToString([]byte(config.Version))
	req.Header.Set("User-Agent", "snyk-ls/"+base64.URLEncoding.EncodeToString([]byte(config.Version)))
	req.Header.Set("x-snyk-ide", "snyk-ls-"+clientID)

	log.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.httpClientFunc().Do(req)
	if err != nil {
		return nil, NewSnykApiError(err.Error(), 0)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("Couldn't close response body in call to Snyk API")
		}
	}(response.Body)

	apiError := checkResponseCode(response)
	if err != nil {
		return nil, apiError
	}

	responseBody, readErr := io.ReadAll(response.Body)
	log.Trace().Str("response.Status", response.Status).Str("responseBody",
		string(responseBody)).Msg("RECEIVED FROM REMOTE")
	if readErr != nil {
		return nil, NewSnykApiError(err.Error(), 0)
	}
	return responseBody, nil
}

func checkResponseCode(r *http.Response) *SnykApiError {
	if r.StatusCode >= 200 && r.StatusCode <= 399 {
		return nil
	}

	return NewSnykApiError("Unexpected response code: "+r.Status, r.StatusCode)
}

package code

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
)

const DefaultEndpointURL = "https://snyk.io/api/"

type SnykApiClientImpl struct {
	host   string
	client http.Client
}

type localCodeEngine struct {
	AllowCloudUpload bool   `json:"allowCloudUpload"`
	Url              string `json:"url"`
	Enabled          bool   `json:"enabled"`
}

type sastResponse struct {
	SastEnabled                 bool            `json:"sastEnabled"`
	LocalCodeEngine             localCodeEngine `json:"localCodeEngine"`
	Org                         string          `json:"org"`
	SupportedLanguages          []string        `json:"supportedLanguages"`
	ReportFalsePositivesEnabled bool            `json:"reportFalsePositivesEnabled"`
}

type SnykApiClient interface {
	SastEnabled() (sastEnabled bool, localCodeEngineEnabled bool, reportFalsePositivesEnabled bool, err error)
}

func NewSnykApiClient(host string) SnykApiClient {
	s := SnykApiClientImpl{
		host: host,
	}
	return &s
}

func (s *SnykApiClientImpl) SastEnabled() (sastEnabled bool, localCodeEngineEnabled bool, reportFalsePositivesEnabled bool, err error) {
	log.Debug().Str("method", "SastEnabled").Msg("API: Getting SastEnabled")
	path := "/cli-config/settings/sast"
	responseBody, err := s.doCall("GET", path, nil)
	if err != nil {
		err = fmt.Errorf("%v: %v", err, responseBody)
		log.Err(err).Str("method", "SastEnabled").Msg("error when calling sastEnabled endpoint")
		return false, false, false, err
	}

	var response sastResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		err = fmt.Errorf("%v: %v", err, responseBody)
		log.Err(err).Str("method", "SastEnabled").Msg("couldn't unmarshal sastResponse")
		return false, false, false, err
	}
	log.Debug().Str("method", "SastEnabled").Msg("API: Done")
	return response.SastEnabled, response.LocalCodeEngine.Enabled, response.ReportFalsePositivesEnabled, nil
}

func (s *SnykApiClientImpl) doCall(method string, path string, requestBody []byte) (responseBody []byte, err error) {
	b := bytes.NewBuffer(requestBody)
	req, err := http.NewRequest(method, s.host+path, b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+config.CurrentConfig().Token())
	req.Header.Set("Content-Type", "application/json")
	clientID := base64.URLEncoding.EncodeToString([]byte(config.Version))
	req.Header.Set("User-Agent", "snyk-ls/"+base64.URLEncoding.EncodeToString([]byte(config.Version)))
	req.Header.Set("x-snyk-ide", "snyk-ls-"+clientID)

	log.Trace().Str("requestBody", string(requestBody)).Msg("SEND TO REMOTE")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("Couldn't close response body in call to Snyk API")
		}
	}(response.Body)
	responseBody, err = ioutil.ReadAll(response.Body)
	log.Trace().Str("responseBody", string(responseBody)).Msg("RECEIVED FROM REMOTE")
	if err != nil {
		return nil, err
	}
	return responseBody, err
}

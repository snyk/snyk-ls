/*
 * Copyright 2022 Snyk Ltd.
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

package httpclient

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/application/config"
)

func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	method := "NewHTTPClient"
	if config.CurrentConfig().CliSettings().Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		log.Info().Str("method", method).Msg("Creating insecure http client")
	}
	client := &http.Client{Transport: tr}
	client.Timeout = 10 * time.Minute
	buffer := bytes.NewBuffer([]byte(""))
	req, err := http.NewRequest("GET", "https://api.snyk.io", buffer)
	if err != nil {
		log.Err(err).Str("method", method).Send()
	}
	proxy, err := tr.Proxy(req)
	if err != nil {
		log.Err(err).Str("method", method).Send()
	}
	if proxy != nil {
		proxySplit := strings.Split(proxy.String(), "@")
		proxyLogString := proxySplit[0]
		if len(proxySplit) > 1 {
			proxyLogString = "xxx@" + proxySplit[1]
		}
		log.Info().Str("method", method).Str("proxy", proxyLogString).Msg("created http client with proxy support")
	}
	return client
}

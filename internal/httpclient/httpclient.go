package httpclient

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/config"
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
	req, err := http.NewRequest("GET", "http://api.snyk.io", buffer)
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

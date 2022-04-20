package httpclient

import (
	"net/http"
)

func NewHTTPClient() *http.Client {
	client := http.DefaultClient
	// TODO: timeouts, proxy etc handling?
	return client
}

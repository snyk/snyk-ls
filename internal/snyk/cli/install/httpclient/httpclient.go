package httpclient

import (
	"net/http"
	"time"
)

func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Minute,
	}
}

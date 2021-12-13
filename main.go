package main

import (
	"github.com/rs/zerolog"
	"github.com/snyk/snyk-lsp/server"
	"time"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimeFieldFormat = time.RFC3339
	server.Start()
}

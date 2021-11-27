package main

import (
	"github.com/snyk/snyk-lsp/server"
	"github.com/snyk/snyk-lsp/util"
)

func main() {
	util.InitLogging()
	defer util.StopLogging()
	server.Start()
}

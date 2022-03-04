package config

import "strconv"

var (
	Version                 = "SNAPSHOT" // set by build via go build -ldflags "-X main.gitinfo=xxx"
	IsErrorReportingEnabled = false
	IsDevelopment, _        = strconv.ParseBool(Development)
	Development             = "true"
)

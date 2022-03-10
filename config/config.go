package config

import "strconv"

var (
	Version                 = "SNAPSHOT"
	IsErrorReportingEnabled = false
	IsDevelopment, _        = strconv.ParseBool(Development)
	Development             = "true"
)

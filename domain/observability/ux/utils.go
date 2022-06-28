package ux

import (
	"github.com/snyk/snyk-ls/application/config"
)

func GetEnabledAnalysisTypes() (analysisTypes []AnalysisType) {
	if config.CurrentConfig().IsSnykIacEnabled() {
		analysisTypes = append(analysisTypes, InfrastructureAsCode)
	}
	if config.CurrentConfig().IsSnykOssEnabled() {
		analysisTypes = append(analysisTypes, OpenSource)
	}
	if config.CurrentConfig().IsSnykCodeEnabled() {
		analysisTypes = append(analysisTypes, CodeSecurity)
	}
	return analysisTypes
}

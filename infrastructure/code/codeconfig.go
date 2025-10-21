package code

import (
	"time"

	"github.com/snyk/snyk-ls/application/config"
)

// CodeConfig provides a concrete implementation of the codeClientConfig.Config interface
// It's lazy and delegates most calls to the language server config, only storing Organization for the folder
type CodeConfig struct {
	orgForFolder string
	lsConfig     *config.Config
}

func (c *CodeConfig) Organization() string {
	return c.orgForFolder
}

func (c *CodeConfig) IsFedramp() bool {
	return c.lsConfig.IsFedramp()
}

func (c *CodeConfig) SnykCodeApi() string {
	return c.lsConfig.SnykCodeApi()
}

func (c *CodeConfig) SnykApi() string {
	return c.lsConfig.SnykApi()
}

func (c *CodeConfig) SnykCodeAnalysisTimeout() time.Duration {
	return c.lsConfig.SnykCodeAnalysisTimeout()
}

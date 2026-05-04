package code

import (
	"time"

	codeClientConfig "github.com/snyk/code-client-go/config"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
)

// CodeConfig provides a concrete implementation of the codeClientConfig.Config interface
// It's lazy and delegates most calls to the language server config, only storing Organization for the folder
type CodeConfig struct {
	orgForFolder string
	lsConfig     *config.Config
	codeApiUrl   string
}

// Compile-time check to ensure CodeConfig implements codeClientConfig.Config
var _ codeClientConfig.Config = (*CodeConfig)(nil)

func (c *CodeConfig) Organization() string {
	return c.orgForFolder
}

func (c *CodeConfig) IsFedramp() bool {
	return c.lsConfig.IsFedramp()
}

func (c *CodeConfig) SnykCodeApi() string {
	gafConfig := c.lsConfig.Engine().GetConfiguration()
	additionalURLs := gafConfig.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, c.codeApiUrl)
	gafConfig.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
	return c.codeApiUrl
}

func (c *CodeConfig) SnykApi() string {
	return c.lsConfig.SnykApi()
}

func (c *CodeConfig) SnykCodeAnalysisTimeout() time.Duration {
	return c.lsConfig.SnykCodeAnalysisTimeout()
}

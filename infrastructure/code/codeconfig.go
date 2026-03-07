package code

import (
	"time"

	codeClientConfig "github.com/snyk/code-client-go/config"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
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
	return c.lsConfig.Engine().GetConfiguration().GetBool(configuration.IS_FEDRAMP)
}

func (c *CodeConfig) SnykCodeApi() string {
	engineConfig := c.lsConfig.Engine().GetConfiguration()
	additionalURLs := engineConfig.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, c.codeApiUrl)
	engineConfig.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
	return c.codeApiUrl
}

func (c *CodeConfig) SnykApi() string {
	return c.lsConfig.Engine().GetConfiguration().GetString(configuration.UserGlobalKey(types.SettingApiEndpoint))
}

func (c *CodeConfig) SnykCodeAnalysisTimeout() time.Duration {
	return config.GetSnykCodeAnalysisTimeout(c.lsConfig.Engine().GetConfiguration())
}

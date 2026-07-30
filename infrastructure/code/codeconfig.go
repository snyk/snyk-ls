package code

import (
	"slices"
	"sync"
	"time"

	codeClientConfig "github.com/snyk/code-client-go/config"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/internal/types"
)

// authURLsMu serializes all read-modify-write operations on the
// AUTHENTICATION_ADDITIONAL_URLS configuration key within this package.
//
// The key is written by two separate paths:
//   - CodeConfig.SnykCodeApi() — called concurrently for each workspace folder
//     scan (each scan creates a new *CodeConfig instance, all sharing the same
//     workflow.Engine and therefore the same configuration object).
//   - updateCodeApiLocalEngine() — called during scan startup and HTTP-client
//     initialization on the same engine configuration.
//
// A package-level mutex is the correct granularity: it provides a single
// exclusion domain for all writers in this package regardless of which
// *CodeConfig instance or call site is involved (IDE-2169).
var authURLsMu sync.Mutex

// CodeConfig provides a concrete implementation of the codeClientConfig.Config interface
// It's lazy and delegates most calls to the language server config, only storing Organization for the folder
type CodeConfig struct {
	orgForFolder   string
	engine         workflow.Engine
	codeApiUrl     string
	configResolver types.ConfigResolverInterface
}

// Compile-time check to ensure CodeConfig implements codeClientConfig.Config
var _ codeClientConfig.Config = (*CodeConfig)(nil)

func (c *CodeConfig) Organization() string {
	return c.orgForFolder
}

func (c *CodeConfig) IsFedramp() bool {
	return c.engine.GetConfiguration().GetBool(configuration.IS_FEDRAMP)
}

func (c *CodeConfig) SnykCodeApi() string {
	authURLsMu.Lock()
	defer authURLsMu.Unlock()
	engineConfig := c.engine.GetConfiguration()
	additionalURLs := engineConfig.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	if !slices.Contains(additionalURLs, c.codeApiUrl) {
		additionalURLs = append(additionalURLs, c.codeApiUrl)
		engineConfig.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)
	}
	return c.codeApiUrl
}

func (c *CodeConfig) SnykApi() string {
	return c.configResolver.GetString(types.SettingApiEndpoint, nil)
}

func (c *CodeConfig) SnykCodeAnalysisTimeout() time.Duration {
	return config.GetSnykCodeAnalysisTimeout(c.engine.GetConfiguration())
}

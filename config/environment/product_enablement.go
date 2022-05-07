package environment

import (
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/snyk/snyk-ls/internal/concurrency"
)

type EnabledProducts struct {
	OpenSource concurrency.AtomicBool
	Code       concurrency.AtomicBool
	Iac        concurrency.AtomicBool
	Container  concurrency.AtomicBool
	Advisor    concurrency.AtomicBool
}

const (
	ActivateSnykOssKey       = "ACTIVATE_SNYK_OPEN_SOURCE"
	ActivateSnykCodeKey      = "ACTIVATE_SNYK_CODE"
	ActivateSnykIacKey       = "ACTIVATE_SNYK_IAC"
	ActivateSnykContainerKey = "ACTIVATE_SNYK_CONTAINER"
	ActivateSnykAdvisorKey   = "ACTIVATE_SNYK_ADVISOR"
)

var CurrentEnabledProducts EnabledProducts
var initializeMutex = &sync.Mutex{}

func init() {
	initializeMutex.Lock()
	CurrentEnabledProducts = EnabledProducts{}
	CurrentEnabledProducts.initializeDefaultProductEnablement()
	initializeMutex.Unlock()
}

func (e *EnabledProducts) initializeDefaultProductEnablement() {
	e.OpenSource.Set(true)
	e.Code.Set(true)
	e.Iac.Set(true)
	e.Container.Set(false)
	e.Advisor.Set(false)
}

func EnabledProductsFromEnv() {
	oss := getValue(ActivateSnykOssKey)
	code := getValue(ActivateSnykCodeKey)
	iac := getValue(ActivateSnykIacKey)
	container := getValue(ActivateSnykContainerKey)
	advisor := getValue(ActivateSnykAdvisorKey)

	if oss != "" {
		parseBool, err := strconv.ParseBool(oss)
		if err != nil {
			log.Warn().Err(err).Str("method", "EnabledProductsFromEnv").Msgf("couldn't parse oss config %s", oss)
		}
		CurrentEnabledProducts.OpenSource.Set(parseBool)
	}

	if code != "" {
		parseBool, err := strconv.ParseBool(code)
		if err != nil {
			log.Warn().Err(err).Str("method", "EnabledProductsFromEnv").Msgf("couldn't parse code config %s", code)
		}
		CurrentEnabledProducts.Code.Set(parseBool)
	}

	if iac != "" {
		parseBool, err := strconv.ParseBool(iac)
		if err != nil {
			log.Warn().Err(err).Str("method", "EnabledProductsFromEnv").Msgf("couldn't parse iac config %s", iac)
		}
		CurrentEnabledProducts.Iac.Set(parseBool)
	}

	if container != "" {
		parseBool, err := strconv.ParseBool(container)
		if err != nil {
			log.Warn().Err(err).Str("method", "EnabledProductsFromEnv").Msgf("couldn't parse container config %s", container)
		}
		CurrentEnabledProducts.Container.Set(parseBool)
	}
	if advisor != "" {
		parseBool, err := strconv.ParseBool(advisor)
		if err != nil {
			log.Warn().Err(err).Str("method", "EnabledProductsFromEnv").Msgf("couldn't parse advisor config %s", advisor)
		}
		CurrentEnabledProducts.Advisor.Set(parseBool)
	}
}

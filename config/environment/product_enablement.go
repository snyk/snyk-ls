package environment

import (
	"context"
	"strconv"
	"sync"

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

func EnabledProductsFromEnv(ctx context.Context) {
	oss := getValue(ActivateSnykOssKey)
	code := getValue(ActivateSnykCodeKey)
	iac := getValue(ActivateSnykIacKey)
	container := getValue(ActivateSnykContainerKey)
	advisor := getValue(ActivateSnykAdvisorKey)

	if oss != "" {
		parseBool, err := strconv.ParseBool(oss)
		if err != nil {
			Logger.
				WithField("method", "EnabledProductsFromEnv").
				WithField("oss", oss).
				Warn(ctx, "couldn't parse config")
		}
		CurrentEnabledProducts.OpenSource.Set(parseBool)
	}

	if code != "" {
		parseBool, err := strconv.ParseBool(code)
		if err != nil {
			Logger.
				WithField("method", "EnabledProductsFromEnv").
				WithField("code", code).
				Warn(ctx, "couldn't parse config")
		}
		CurrentEnabledProducts.Code.Set(parseBool)
	}

	if iac != "" {
		parseBool, err := strconv.ParseBool(iac)
		if err != nil {
			Logger.
				WithField("method", "EnabledProductsFromEnv").
				WithField("iac", iac).
				Warn(ctx, "couldn't parse config")
		}
		CurrentEnabledProducts.Iac.Set(parseBool)
	}

	if container != "" {
		parseBool, err := strconv.ParseBool(container)
		if err != nil {
			Logger.
				WithField("method", "EnabledProductsFromEnv").
				WithField("container", container).
				Warn(ctx, "couldn't parse config")
		}
		CurrentEnabledProducts.Container.Set(parseBool)
	}
	if advisor != "" {
		parseBool, err := strconv.ParseBool(advisor)
		if err != nil {
			Logger.
				WithField("method", "EnabledProductsFromEnv").
				WithField("advisor", advisor).
				Warn(ctx, "couldn't parse config")
		}
		CurrentEnabledProducts.Advisor.Set(parseBool)
	}
}

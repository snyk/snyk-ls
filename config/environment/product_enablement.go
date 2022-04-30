package environment

import "strconv"

type EnabledProducts struct {
	OpenSource bool
	Code       bool
	Iac        bool
	Container  bool
	Advisor    bool
}

const (
	ActivateSnykOssKey       = "ACTIVATE_SNYK_OPEN_SOURCE"
	ActivateSnykCodeKey      = "ACTIVATE_SNYK_CODE"
	ActivateSnykIacKey       = "ACTIVATE_SNYK_IAC"
	ActivateSnykContainerKey = "ACTIVATE_SNYK_CONTAINER"
	ActivateSnykAdvisorKey   = "ACTIVATE_SNYK_ADVISOR"
)

var CurrentEnabledProducts = EnabledProductsFromEnv()

func EnabledProductsFromEnv() EnabledProducts {
	oss := getValue(ActivateSnykOssKey)
	code := getValue(ActivateSnykCodeKey)
	iac := getValue(ActivateSnykIacKey)
	container := getValue(ActivateSnykContainerKey)
	advisor := getValue(ActivateSnykAdvisorKey)

	var enabledProducts = EnabledProducts{OpenSource: true, Code: true, Iac: true, Container: false, Advisor: false}
	if oss != "" {
		enabledProducts.OpenSource, _ = strconv.ParseBool(oss)
	}
	if code != "" {
		enabledProducts.Code, _ = strconv.ParseBool(code)
	}
	if iac != "" {
		enabledProducts.Iac, _ = strconv.ParseBool(iac)
	}
	if container != "" {
		enabledProducts.Container, _ = strconv.ParseBool(container)
	}
	if advisor != "" {
		enabledProducts.Advisor, _ = strconv.ParseBool(advisor)
	}

	return enabledProducts
}

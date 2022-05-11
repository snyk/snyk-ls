package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykCodeKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykIacKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykContainerKey, "set it to anything to make sure it is reset")
	t.Setenv(ActivateSnykAdvisorKey, "set it to anything to make sure it is reset")
	os.Unsetenv(ActivateSnykOssKey)
	os.Unsetenv(ActivateSnykCodeKey)
	os.Unsetenv(ActivateSnykIacKey)
	os.Unsetenv(ActivateSnykContainerKey)
	os.Unsetenv(ActivateSnykAdvisorKey)
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.OpenSource.Get())
	assert.Equal(t, false, CurrentEnabledProducts.Code.Get())
	assert.Equal(t, true, CurrentEnabledProducts.Iac.Get())
	assert.Equal(t, false, CurrentEnabledProducts.Container.Get())
	assert.Equal(t, false, CurrentEnabledProducts.Advisor.Get())
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "false")
	t.Setenv(ActivateSnykCodeKey, "true")
	t.Setenv(ActivateSnykIacKey, "false")
	t.Setenv(ActivateSnykAdvisorKey, "true")
	t.Setenv(ActivateSnykContainerKey, "true")

	CurrentEnabledProducts = EnabledProducts{}
	CurrentEnabledProducts.initializeDefaultProductEnablement()

	assert.Equal(t, false, CurrentEnabledProducts.OpenSource.Get())
	assert.Equal(t, true, CurrentEnabledProducts.Code.Get())
	assert.Equal(t, false, CurrentEnabledProducts.Iac.Get())
	assert.Equal(t, true, CurrentEnabledProducts.Container.Get())
	assert.Equal(t, true, CurrentEnabledProducts.Advisor.Get())
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "false")
	EnabledProductsFromEnv()
	assert.Equal(t, false, CurrentEnabledProducts.OpenSource.Get())

	t.Setenv(ActivateSnykOssKey, "true")
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.OpenSource.Get())
}

func TestGetEnabledProducts_Code(t *testing.T) {
	t.Setenv(ActivateSnykCodeKey, "false")
	EnabledProductsFromEnv()
	assert.Equal(t, false, CurrentEnabledProducts.Code.Get())

	t.Setenv(ActivateSnykCodeKey, "true")
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.Code.Get())
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	t.Setenv(ActivateSnykIacKey, "false")
	EnabledProductsFromEnv()
	assert.Equal(t, false, CurrentEnabledProducts.Iac.Get())

	t.Setenv(ActivateSnykIacKey, "true")
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.Iac.Get())
}

func TestGetEnabledProducts_Container(t *testing.T) {
	t.Setenv(ActivateSnykContainerKey, "false")
	EnabledProductsFromEnv()
	assert.Equal(t, false, CurrentEnabledProducts.Container.Get())

	t.Setenv(ActivateSnykContainerKey, "true")
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.Container.Get())
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	t.Setenv(ActivateSnykAdvisorKey, "false")
	EnabledProductsFromEnv()
	assert.Equal(t, false, CurrentEnabledProducts.Advisor.Get())

	t.Setenv(ActivateSnykAdvisorKey, "true")
	EnabledProductsFromEnv()
	assert.Equal(t, true, CurrentEnabledProducts.Advisor.Get())
}

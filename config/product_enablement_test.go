package config

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

	CurrentConfig.enabledProductsFromEnv()

	assert.Equal(t, true, CurrentConfig.IsSnykOssEnabled())
	assert.Equal(t, false, CurrentConfig.IsSnykCodeEnabled())
	assert.Equal(t, true, CurrentConfig.IsSnykIacEnabled())
	assert.Equal(t, false, CurrentConfig.IsSnykContainerEnabled())
	assert.Equal(t, false, CurrentConfig.IsSnykAdvisorEnabled())
}

func TestInitializeDefaultProductEnablement(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "false")
	t.Setenv(ActivateSnykCodeKey, "true")
	t.Setenv(ActivateSnykIacKey, "false")
	t.Setenv(ActivateSnykAdvisorKey, "true")
	t.Setenv(ActivateSnykContainerKey, "true")

	CurrentConfig = New()

	assert.Equal(t, false, CurrentConfig.IsSnykOssEnabled())
	assert.Equal(t, true, CurrentConfig.IsSnykCodeEnabled())
	assert.Equal(t, false, CurrentConfig.IsSnykIacEnabled())
	assert.Equal(t, true, CurrentConfig.IsSnykContainerEnabled())
	assert.Equal(t, true, CurrentConfig.IsSnykAdvisorEnabled())
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "false")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, false, CurrentConfig.isSnykOssEnabled.Get())

	t.Setenv(ActivateSnykOssKey, "true")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, true, CurrentConfig.isSnykOssEnabled.Get())
}

func TestGetEnabledProducts_Code(t *testing.T) {
	t.Setenv(ActivateSnykCodeKey, "false")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, false, CurrentConfig.IsSnykCodeEnabled())

	t.Setenv(ActivateSnykCodeKey, "true")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, true, CurrentConfig.IsSnykCodeEnabled())
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	t.Setenv(ActivateSnykIacKey, "false")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, false, CurrentConfig.IsSnykIacEnabled())

	t.Setenv(ActivateSnykIacKey, "true")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, true, CurrentConfig.IsSnykIacEnabled())
}

func TestGetEnabledProducts_Container(t *testing.T) {
	t.Setenv(ActivateSnykContainerKey, "false")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, false, CurrentConfig.IsSnykContainerEnabled())

	t.Setenv(ActivateSnykContainerKey, "true")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, true, CurrentConfig.IsSnykContainerEnabled())
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	t.Setenv(ActivateSnykAdvisorKey, "false")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, false, CurrentConfig.IsSnykAdvisorEnabled())

	t.Setenv(ActivateSnykAdvisorKey, "true")
	CurrentConfig.enabledProductsFromEnv()
	assert.Equal(t, true, CurrentConfig.IsSnykAdvisorEnabled())
}

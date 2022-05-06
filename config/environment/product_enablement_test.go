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
	assert.Equal(t, true, EnabledProductsFromEnv().OpenSource)
	assert.Equal(t, true, EnabledProductsFromEnv().Code)
	assert.Equal(t, true, EnabledProductsFromEnv().Iac)
	assert.Equal(t, false, EnabledProductsFromEnv().Container)
	assert.Equal(t, false, EnabledProductsFromEnv().Advisor)
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	t.Setenv(ActivateSnykOssKey, "false")
	assert.Equal(t, false, EnabledProductsFromEnv().OpenSource)

	t.Setenv(ActivateSnykOssKey, "true")
	assert.Equal(t, true, EnabledProductsFromEnv().OpenSource)
}

func TestGetEnabledProducts_Code(t *testing.T) {
	t.Setenv(ActivateSnykCodeKey, "false")
	assert.Equal(t, false, EnabledProductsFromEnv().Code)

	t.Setenv(ActivateSnykCodeKey, "true")
	assert.Equal(t, true, EnabledProductsFromEnv().Code)
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	t.Setenv(ActivateSnykIacKey, "false")
	assert.Equal(t, false, EnabledProductsFromEnv().Iac)

	t.Setenv(ActivateSnykIacKey, "true")
	assert.Equal(t, true, EnabledProductsFromEnv().Iac)
}

func TestGetEnabledProducts_Container(t *testing.T) {
	t.Setenv(ActivateSnykContainerKey, "false")
	assert.Equal(t, false, EnabledProductsFromEnv().Container)

	t.Setenv(ActivateSnykContainerKey, "true")
	assert.Equal(t, true, EnabledProductsFromEnv().Container)
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	t.Setenv(ActivateSnykAdvisorKey, "false")
	assert.Equal(t, false, EnabledProductsFromEnv().Advisor)

	t.Setenv(ActivateSnykAdvisorKey, "true")
	assert.Equal(t, true, EnabledProductsFromEnv().Advisor)
}

package environment

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnabledProducts_DefaultValues(t *testing.T) {
	os.Clearenv()
	assert.Equal(t, true, EnabledProductsFromEnv().OpenSource)
	assert.Equal(t, true, EnabledProductsFromEnv().Code)
	assert.Equal(t, true, EnabledProductsFromEnv().Iac)
	assert.Equal(t, false, EnabledProductsFromEnv().Container)
	assert.Equal(t, false, EnabledProductsFromEnv().Advisor)
}

func TestGetEnabledProducts_Oss(t *testing.T) {
	os.Clearenv()
	defer os.Clearenv()
	err := os.Setenv(ActivateSnykOssKey, "false")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, false, EnabledProductsFromEnv().OpenSource)

	err = os.Setenv(ActivateSnykOssKey, "true")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, true, EnabledProductsFromEnv().OpenSource)
}

func TestGetEnabledProducts_Code(t *testing.T) {
	os.Clearenv()
	defer os.Clearenv()
	err := os.Setenv(ActivateSnykCodeKey, "false")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, false, EnabledProductsFromEnv().Code)

	err = os.Setenv(ActivateSnykCodeKey, "true")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, true, EnabledProductsFromEnv().Code)
}

func TestGetEnabledProducts_Iac(t *testing.T) {
	os.Clearenv()
	defer os.Clearenv()
	err := os.Setenv(ActivateSnykIacKey, "false")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, false, EnabledProductsFromEnv().Iac)

	err = os.Setenv(ActivateSnykIacKey, "true")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, true, EnabledProductsFromEnv().Iac)
}

func TestGetEnabledProducts_Container(t *testing.T) {
	os.Clearenv()
	defer os.Clearenv()
	err := os.Setenv(ActivateSnykContainerKey, "false")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, false, EnabledProductsFromEnv().Container)

	err = os.Setenv(ActivateSnykContainerKey, "true")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, true, EnabledProductsFromEnv().Container)
}

func TestGetEnabledProducts_Advisor(t *testing.T) {
	os.Clearenv()
	defer os.Clearenv()
	err := os.Setenv(ActivateSnykAdvisorKey, "false")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, false, EnabledProductsFromEnv().Advisor)

	err = os.Setenv(ActivateSnykAdvisorKey, "true")
	if err != nil {
		t.Fatal("couldn't set environment")
	}
	assert.Equal(t, true, EnabledProductsFromEnv().Advisor)
}

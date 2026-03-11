package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDidChangeConfigurationParams_UnmarshalJSON_OldFormat(t *testing.T) {
	oldPayload := []byte(`{"settings": {"token": "old-token", "activateSnykOpenSource": "false", "folderConfigs": [{"folderPath": "/test"}]}}`)
	var params DidChangeConfigurationParams
	err := json.Unmarshal(oldPayload, &params)
	assert.NoError(t, err)

	assert.NotNil(t, params.Settings)
	assert.Equal(t, "old-token", params.Settings["token"].Value)
	assert.True(t, params.Settings["token"].Changed)

	assert.Equal(t, "false", params.Settings["activateSnykOpenSource"].Value)

	assert.Len(t, params.FolderConfigs, 1)
	assert.Equal(t, FilePath("/test"), params.FolderConfigs[0].FolderPath)
}

func TestDidChangeConfigurationParams_UnmarshalJSON_NewFormat(t *testing.T) {
	newPayload := []byte(`{"settings": {"token": {"value": "new-token", "changed": true}}, "folderConfigs": [{"folderPath": "/test"}]}`)
	var params DidChangeConfigurationParams
	err := json.Unmarshal(newPayload, &params)
	assert.NoError(t, err)

	assert.NotNil(t, params.Settings)
	assert.Equal(t, "new-token", params.Settings["token"].Value)
	assert.True(t, params.Settings["token"].Changed)

	assert.Len(t, params.FolderConfigs, 1)
	assert.Equal(t, FilePath("/test"), params.FolderConfigs[0].FolderPath)
}

func TestDidChangeConfigurationParams_UnmarshalJSON_NewFormat_NullValue(t *testing.T) {
	payload := []byte(`{"settings": {"snyk_code_enabled": {"value": null, "changed": true}}}`)
	var params DidChangeConfigurationParams
	err := json.Unmarshal(payload, &params)
	assert.NoError(t, err)

	cs := params.Settings["snyk_code_enabled"]
	assert.NotNil(t, cs)
	assert.True(t, cs.Changed, "changed must be true for reset-to-default")
	assert.Nil(t, cs.Value, "value must be nil for reset-to-default, not the raw map")
}

func TestDidChangeConfigurationParams_UnmarshalJSON_NewFormat_FalseValue(t *testing.T) {
	payload := []byte(`{"settings": {"snyk_code_enabled": {"value": false, "changed": true}}}`)
	var params DidChangeConfigurationParams
	err := json.Unmarshal(payload, &params)
	assert.NoError(t, err)

	cs := params.Settings["snyk_code_enabled"]
	assert.NotNil(t, cs)
	assert.True(t, cs.Changed)
	assert.Equal(t, false, cs.Value)
}

func TestInitializationOptions_UnmarshalJSON_NewFormat_NullValue(t *testing.T) {
	payload := []byte(`{"settings": {"snyk_code_enabled": {"value": null, "changed": true}}, "integrationName": "JETBRAINS"}`)
	var params InitializationOptions
	err := json.Unmarshal(payload, &params)
	assert.NoError(t, err)

	cs := params.Settings["snyk_code_enabled"]
	assert.NotNil(t, cs)
	assert.True(t, cs.Changed, "changed must be true for reset-to-default")
	assert.Nil(t, cs.Value, "value must be nil for reset-to-default, not the raw map")
}

func TestInitializationOptions_UnmarshalJSON_OldFormat(t *testing.T) {
	oldPayload := []byte(`{"token": "old-token", "activateSnykOpenSource": "false", "folderConfigs": [{"folderPath": "/test"}], "integrationName": "ECLIPSE"}`)
	var params InitializationOptions
	err := json.Unmarshal(oldPayload, &params)
	assert.NoError(t, err)

	assert.NotNil(t, params.Settings)
	assert.Equal(t, "old-token", params.Settings["token"].Value)
	assert.True(t, params.Settings["token"].Changed)

	assert.Equal(t, "false", params.Settings["activateSnykOpenSource"].Value)
	assert.Equal(t, "ECLIPSE", params.IntegrationName)

	assert.Len(t, params.FolderConfigs, 1)
	assert.Equal(t, FilePath("/test"), params.FolderConfigs[0].FolderPath)
}

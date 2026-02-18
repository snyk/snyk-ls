/*
 * © 2022-2026 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullableField_UnmarshalJSON(t *testing.T) {
	t.Run("field omitted results in IsOmitted=true", func(t *testing.T) {
		jsonBlob := `{"name": "test"}`

		type TestStruct struct {
			Name  string              `json:"name"`
			Value NullableField[bool] `json:"value,omitempty"`
		}

		var result TestStruct
		err := json.Unmarshal([]byte(jsonBlob), &result)

		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
		assert.True(t, result.Value.IsOmitted(), "Omitted field should have IsOmitted()=true")
		assert.False(t, result.Value.IsNull(), "Omitted field should have IsNull()=false")
		assert.False(t, result.Value.HasValue(), "Omitted field should have HasValue()=false")
	})

	t.Run("explicit null results in IsNull=true", func(t *testing.T) {
		jsonBlob := `{"name": "test", "value": null}`

		type TestStruct struct {
			Name  string              `json:"name"`
			Value NullableField[bool] `json:"value,omitempty"`
		}

		var result TestStruct
		err := json.Unmarshal([]byte(jsonBlob), &result)

		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
		assert.False(t, result.Value.IsOmitted(), "Null field should have IsOmitted()=false")
		assert.True(t, result.Value.IsNull(), "Null field should have IsNull()=true")
		assert.False(t, result.Value.HasValue(), "Null field should have HasValue()=false")
	})

	t.Run("explicit value results in HasValue=true", func(t *testing.T) {
		jsonBlob := `{"name": "test", "value": true}`

		type TestStruct struct {
			Name  string              `json:"name"`
			Value NullableField[bool] `json:"value,omitempty"`
		}

		var result TestStruct
		err := json.Unmarshal([]byte(jsonBlob), &result)

		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
		assert.False(t, result.Value.IsOmitted(), "Value field should have IsOmitted()=false")
		assert.False(t, result.Value.IsNull(), "Value field should have IsNull()=false")
		assert.True(t, result.Value.HasValue(), "Value field should have HasValue()=true")
		assert.True(t, result.Value.Value, "Value should be true")
	})

	t.Run("explicit false value is distinguishable from null", func(t *testing.T) {
		jsonBlob := `{"name": "test", "value": false}`

		type TestStruct struct {
			Name  string              `json:"name"`
			Value NullableField[bool] `json:"value,omitempty"`
		}

		var result TestStruct
		err := json.Unmarshal([]byte(jsonBlob), &result)

		require.NoError(t, err)
		assert.True(t, result.Value.HasValue(), "False value should have HasValue()=true")
		assert.False(t, result.Value.IsNull(), "False value should have IsNull()=false")
		assert.False(t, result.Value.Value, "Value should be false")
	})

	t.Run("int: zero value is distinguishable from null", func(t *testing.T) {
		type TestStruct struct {
			Threshold NullableField[int] `json:"threshold,omitempty"`
		}

		var zeroValue TestStruct
		err := json.Unmarshal([]byte(`{"threshold": 0}`), &zeroValue)
		require.NoError(t, err)
		assert.True(t, zeroValue.Threshold.HasValue(), "Zero should have HasValue()=true")
		assert.False(t, zeroValue.Threshold.IsNull(), "Zero should have IsNull()=false")
		assert.Equal(t, 0, zeroValue.Threshold.Value)

		var nullValue TestStruct
		err = json.Unmarshal([]byte(`{"threshold": null}`), &nullValue)
		require.NoError(t, err)
		assert.True(t, nullValue.Threshold.IsNull(), "Null should have IsNull()=true")
		assert.False(t, nullValue.Threshold.HasValue(), "Null should have HasValue()=false")
	})

	t.Run("string: empty string is distinguishable from null", func(t *testing.T) {
		type TestStruct struct {
			Name NullableField[string] `json:"name,omitempty"`
		}

		var emptyString TestStruct
		err := json.Unmarshal([]byte(`{"name": ""}`), &emptyString)
		require.NoError(t, err)
		assert.True(t, emptyString.Name.HasValue(), "Empty string should have HasValue()=true")
		assert.False(t, emptyString.Name.IsNull(), "Empty string should have IsNull()=false")
		assert.Equal(t, "", emptyString.Name.Value)

		var nullValue TestStruct
		err = json.Unmarshal([]byte(`{"name": null}`), &nullValue)
		require.NoError(t, err)
		assert.True(t, nullValue.Name.IsNull(), "Null should have IsNull()=true")
	})

	t.Run("works with struct type (SeverityFilter)", func(t *testing.T) {
		type TestStruct struct {
			Filter NullableField[SeverityFilter] `json:"filter,omitempty"`
		}

		// Omitted
		var omitted TestStruct
		err := json.Unmarshal([]byte(`{}`), &omitted)
		require.NoError(t, err)
		assert.True(t, omitted.Filter.IsOmitted())

		// Null
		var nullVal TestStruct
		err = json.Unmarshal([]byte(`{"filter": null}`), &nullVal)
		require.NoError(t, err)
		assert.True(t, nullVal.Filter.IsNull())

		// Value
		var withValue TestStruct
		err = json.Unmarshal([]byte(`{"filter": {"critical": true, "high": true, "medium": false, "low": false}}`), &withValue)
		require.NoError(t, err)
		assert.True(t, withValue.Filter.HasValue())
		assert.True(t, withValue.Filter.Value.Critical)
		assert.True(t, withValue.Filter.Value.High)
		assert.False(t, withValue.Filter.Value.Medium)
		assert.False(t, withValue.Filter.Value.Low)
	})
}

func TestNullableField_MarshalJSON(t *testing.T) {
	t.Run("marshals value correctly", func(t *testing.T) {
		type TestStruct struct {
			Value NullableField[bool] `json:"value,omitempty"`
		}

		s := TestStruct{
			Value: NullableField[bool]{Value: true, Present: true},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"value": true}`, string(data))
	})

	t.Run("marshals null correctly", func(t *testing.T) {
		type TestStruct struct {
			Value NullableField[bool] `json:"value"` // No omitempty to ensure field is included
		}

		s := TestStruct{
			Value: NullableField[bool]{Present: true, Null: true},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"value": null}`, string(data))
	})

	t.Run("zero-value NullableField is NOT omitted from plain structs (omitempty limitation)", func(t *testing.T) {
		// omitempty does not omit struct-typed fields. Only LspFolderConfig.MarshalJSON handles
		// correct omission. This test documents the known limitation of plain structs.
		type TestStruct struct {
			Name  string              `json:"name"`
			Value NullableField[bool] `json:"value,omitempty"`
		}
		s := TestStruct{Name: "test", Value: NullableField[bool]{Present: false}}
		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"name":"test"`)
		assert.Contains(t, string(data), `"value"`) // NOT omitted — omitempty doesn't work for structs
	})

	t.Run("marshals false value correctly (not as null)", func(t *testing.T) {
		type TestStruct struct {
			Value NullableField[bool] `json:"value"`
		}

		s := TestStruct{
			Value: NullableField[bool]{Value: false, Present: true},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"value": false}`, string(data))
	})

	t.Run("marshals int value correctly", func(t *testing.T) {
		type TestStruct struct {
			Threshold NullableField[int] `json:"threshold"`
		}

		s := TestStruct{
			Threshold: NullableField[int]{Value: 42, Present: true},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"threshold": 42}`, string(data))
	})

	t.Run("marshals zero int correctly (not as null)", func(t *testing.T) {
		type TestStruct struct {
			Threshold NullableField[int] `json:"threshold"`
		}

		s := TestStruct{
			Threshold: NullableField[int]{Value: 0, Present: true},
		}

		data, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"threshold": 0}`, string(data))
	})
}

func TestNullableField_RoundTrip(t *testing.T) {
	t.Run("round-trips value correctly", func(t *testing.T) {
		type TestStruct struct {
			Value NullableField[bool] `json:"value"`
		}

		original := TestStruct{
			Value: NullableField[bool]{Value: true, Present: true},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var result TestStruct
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.True(t, result.Value.HasValue())
		assert.Equal(t, original.Value.Value, result.Value.Value)
	})

	t.Run("round-trips null correctly", func(t *testing.T) {
		type TestStruct struct {
			Value NullableField[bool] `json:"value"`
		}

		original := TestStruct{
			Value: NullableField[bool]{Present: true, Null: true},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var result TestStruct
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		assert.True(t, result.Value.IsNull())
	})
}

func TestLspFolderConfig_MarshalJSON(t *testing.T) {
	t.Run("Present=false NullableFields are omitted", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"folderPath"`)
		assert.NotContains(t, jsonStr, `"scanAutomatic"`)
		assert.NotContains(t, jsonStr, `"scanNetNew"`)
		assert.NotContains(t, jsonStr, `"snykCodeEnabled"`)
		assert.NotContains(t, jsonStr, `"snykOssEnabled"`)
		assert.NotContains(t, jsonStr, `"snykIacEnabled"`)
		assert.NotContains(t, jsonStr, `"riskScoreThreshold"`)
		assert.NotContains(t, jsonStr, `"enabledSeverities"`)
		assert.NotContains(t, jsonStr, `"issueViewOpenIssues"`)
		assert.NotContains(t, jsonStr, `"issueViewIgnoredIssues"`)
		assert.NotContains(t, jsonStr, `"cweIds"`)
		assert.NotContains(t, jsonStr, `"cveIds"`)
		assert.NotContains(t, jsonStr, `"ruleIds"`)
	})

	t.Run("Present=true value fields are included", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath:         "/path/to/folder",
			ScanAutomatic:      NullableField[bool]{Present: true, Value: true},
			SnykCodeEnabled:    NullableField[bool]{Present: true, Value: false},
			RiskScoreThreshold: NullableField[int]{Present: true, Value: 42},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"scanAutomatic":true`)
		assert.Contains(t, jsonStr, `"snykCodeEnabled":false`)
		assert.Contains(t, jsonStr, `"riskScoreThreshold":42`)
		// Omitted fields remain absent
		assert.NotContains(t, jsonStr, `"scanNetNew"`)
		assert.NotContains(t, jsonStr, `"snykOssEnabled"`)
	})

	t.Run("Present=true null fields appear as null", func(t *testing.T) {
		config := LspFolderConfig{
			FolderPath:      "/path/to/folder",
			ScanAutomatic:   NullableField[bool]{Present: true, Null: true},
			SnykCodeEnabled: NullableField[bool]{Present: true, Null: true},
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"scanAutomatic":null`)
		assert.Contains(t, jsonStr, `"snykCodeEnabled":null`)
		// Other NullableFields remain absent
		assert.NotContains(t, jsonStr, `"scanNetNew"`)
	})

	t.Run("non-NullableField pointer fields still use omitempty", func(t *testing.T) {
		baseBranch := "main"
		config := LspFolderConfig{
			FolderPath: "/path/to/folder",
			BaseBranch: &baseBranch,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"baseBranch":"main"`)
		assert.NotContains(t, jsonStr, `"additionalEnv"`)
		assert.NotContains(t, jsonStr, `"localBranches"`)
	})

	t.Run("round-trip preserves all three NullableField states", func(t *testing.T) {
		original := LspFolderConfig{
			FolderPath:    "/path/to/folder",
			ScanAutomatic: NullableField[bool]{Present: true, Value: true}, // value state
			ScanNetNew:    NullableField[bool]{Present: true, Null: true},  // null state
			// SnykCodeEnabled: zero value (omitted state)
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var result LspFolderConfig
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)

		// value state preserved
		assert.True(t, result.ScanAutomatic.HasValue())
		assert.True(t, result.ScanAutomatic.Value)
		// null state preserved
		assert.True(t, result.ScanNetNew.IsNull())
		// omitted state preserved
		assert.True(t, result.SnykCodeEnabled.IsOmitted())
	})
}

func TestLspFolderConfig_UnmarshalJSON_PatchSemantics(t *testing.T) {
	t.Run("omitted fields are not present", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder"
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		assert.Equal(t, FilePath("/path/to/folder"), config.FolderPath)
		assert.True(t, config.ScanAutomatic.IsOmitted(), "ScanAutomatic should be omitted")
		assert.True(t, config.ScanNetNew.IsOmitted(), "ScanNetNew should be omitted")
		assert.True(t, config.SnykCodeEnabled.IsOmitted(), "SnykCodeEnabled should be omitted")
	})

	t.Run("null fields indicate clear override", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"scanAutomatic": null,
			"snykCodeEnabled": null
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		assert.True(t, config.ScanAutomatic.IsNull(), "ScanAutomatic should be null (clear override)")
		assert.True(t, config.SnykCodeEnabled.IsNull(), "SnykCodeEnabled should be null (clear override)")
		assert.True(t, config.ScanNetNew.IsOmitted(), "ScanNetNew should be omitted (don't change)")
	})

	t.Run("value fields indicate set override", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"scanAutomatic": true,
			"scanNetNew": false,
			"snykCodeEnabled": true
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		assert.True(t, config.ScanAutomatic.HasValue(), "ScanAutomatic should have value")
		assert.True(t, config.ScanAutomatic.Value, "ScanAutomatic value should be true")
		assert.True(t, config.ScanNetNew.HasValue(), "ScanNetNew should have value")
		assert.False(t, config.ScanNetNew.Value, "ScanNetNew value should be false")
		assert.True(t, config.SnykCodeEnabled.HasValue(), "SnykCodeEnabled should have value")
		assert.True(t, config.SnykCodeEnabled.Value, "SnykCodeEnabled value should be true")
	})

	t.Run("mixed omitted, null, and value fields", func(t *testing.T) {
		jsonBlob := `{
			"folderPath": "/path/to/folder",
			"scanAutomatic": true,
			"scanNetNew": null,
			"riskScoreThreshold": 70
		}`

		var config LspFolderConfig
		err := json.Unmarshal([]byte(jsonBlob), &config)

		require.NoError(t, err)
		// Value
		assert.True(t, config.ScanAutomatic.HasValue(), "ScanAutomatic should have value")
		assert.True(t, config.ScanAutomatic.Value)
		// Null (clear)
		assert.True(t, config.ScanNetNew.IsNull(), "ScanNetNew should be null")
		// Value (int)
		assert.True(t, config.RiskScoreThreshold.HasValue(), "RiskScoreThreshold should have value")
		assert.Equal(t, 70, config.RiskScoreThreshold.Value)
		// Omitted
		assert.True(t, config.SnykCodeEnabled.IsOmitted(), "SnykCodeEnabled should be omitted")
		assert.True(t, config.SnykOssEnabled.IsOmitted(), "SnykOssEnabled should be omitted")
	})
}

func TestLspFolderConfig_MarshalJSON_AllNullableFieldsOmittedWhenZero(t *testing.T) {
	config := LspFolderConfig{}

	data, err := json.Marshal(config)
	require.NoError(t, err)

	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &m))

	type omittable interface{ IsOmitted() bool }
	v := reflect.ValueOf(config)
	rt := reflect.TypeOf(config)
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		fv := v.Field(i)
		if _, ok := fv.Interface().(omittable); !ok {
			continue
		}
		jsonTag := field.Tag.Get("json")
		jsonKey := strings.SplitN(jsonTag, ",", 2)[0]
		if jsonKey == "" || jsonKey == "-" {
			continue
		}
		_, present := m[jsonKey]
		assert.False(t, present,
			"NullableField %q (json:%q) must be omitted from JSON output when zero-value; "+
				"ensure MarshalJSON handles it automatically",
			field.Name, jsonKey)
	}
}

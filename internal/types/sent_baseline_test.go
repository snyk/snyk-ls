/*
 * © 2026 Snyk Limited
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSentConfigBaseline_FolderValues(t *testing.T) {
	t.Run("IsFolderEcho returns false when no baseline exists for folder", func(t *testing.T) {
		b := NewSentConfigBaseline()
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, true))
	})

	t.Run("IsFolderEcho returns false when setting not recorded for folder", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingSnykOssEnabled, true)
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, true))
	})

	t.Run("IsFolderEcho returns true when value matches recorded", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingSnykCodeEnabled, true)
		assert.True(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, true))
	})

	t.Run("IsFolderEcho returns false when value differs from recorded", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingSnykCodeEnabled, true)
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, false))
	})

	t.Run("RecordFolderValue overwrites previous value", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingSnykCodeEnabled, true)
		b.RecordFolderValue("/folder", SettingSnykCodeEnabled, false)
		assert.True(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, false))
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, true))
	})

	t.Run("ClearFolder removes all entries for folder", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingSnykCodeEnabled, true)
		b.RecordFolderValue("/folder", SettingSnykOssEnabled, true)
		b.ClearFolder("/folder")
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykCodeEnabled, true))
		assert.False(t, b.IsFolderEcho("/folder", SettingSnykOssEnabled, true))
	})

	t.Run("ClearFolder does not affect other folders", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder1", SettingSnykCodeEnabled, true)
		b.RecordFolderValue("/folder2", SettingSnykCodeEnabled, false)
		b.ClearFolder("/folder1")
		assert.False(t, b.IsFolderEcho("/folder1", SettingSnykCodeEnabled, true))
		assert.True(t, b.IsFolderEcho("/folder2", SettingSnykCodeEnabled, false))
	})

	t.Run("multiple folders are tracked independently", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder1", SettingSnykCodeEnabled, true)
		b.RecordFolderValue("/folder2", SettingSnykCodeEnabled, false)
		assert.True(t, b.IsFolderEcho("/folder1", SettingSnykCodeEnabled, true))
		assert.True(t, b.IsFolderEcho("/folder2", SettingSnykCodeEnabled, false))
		assert.False(t, b.IsFolderEcho("/folder1", SettingSnykCodeEnabled, false))
		assert.False(t, b.IsFolderEcho("/folder2", SettingSnykCodeEnabled, true))
	})
}

func TestSentConfigBaseline_GlobalValues(t *testing.T) {
	t.Run("IsGlobalEcho returns false when no baseline exists", func(t *testing.T) {
		b := NewSentConfigBaseline()
		assert.False(t, b.IsGlobalEcho(SettingSnykCodeEnabled, true))
	})

	t.Run("IsGlobalEcho returns true when value matches recorded", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordGlobalValue(SettingSnykCodeEnabled, true)
		assert.True(t, b.IsGlobalEcho(SettingSnykCodeEnabled, true))
	})

	t.Run("IsGlobalEcho returns false when value differs", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordGlobalValue(SettingSnykCodeEnabled, true)
		assert.False(t, b.IsGlobalEcho(SettingSnykCodeEnabled, false))
	})

	t.Run("RecordGlobalValue overwrites previous value", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordGlobalValue(SettingSnykCodeEnabled, true)
		b.RecordGlobalValue(SettingSnykCodeEnabled, false)
		assert.True(t, b.IsGlobalEcho(SettingSnykCodeEnabled, false))
		assert.False(t, b.IsGlobalEcho(SettingSnykCodeEnabled, true))
	})
}

func TestSentConfigBaseline_TypeCoercion(t *testing.T) {
	t.Run("RiskScoreThreshold: int vs float64 are equal", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingRiskScoreThreshold, 500)
		// IDE may echo back as float64 from JSON
		assert.True(t, b.IsFolderEcho("/folder", SettingRiskScoreThreshold, float64(500)))
	})

	t.Run("RiskScoreThreshold: different values are not equal", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingRiskScoreThreshold, 500)
		assert.False(t, b.IsFolderEcho("/folder", SettingRiskScoreThreshold, float64(600)))
	})

	t.Run("EnabledSeverities: SeverityFilter vs *SeverityFilter are equal", func(t *testing.T) {
		sf := SeverityFilter{Critical: true, High: true, Medium: false, Low: false}
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingEnabledSeverities, sf)
		assert.True(t, b.IsFolderEcho("/folder", SettingEnabledSeverities, &sf))
	})

	t.Run("EnabledSeverities: different values are not equal", func(t *testing.T) {
		sf := SeverityFilter{Critical: true, High: true, Medium: false, Low: false}
		other := SeverityFilter{Critical: true, High: false, Medium: false, Low: false}
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingEnabledSeverities, sf)
		assert.False(t, b.IsFolderEcho("/folder", SettingEnabledSeverities, other))
	})

	t.Run("CweIds: []string slice comparison", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordFolderValue("/folder", SettingCweIds, []string{"CWE-79", "CWE-89"})
		assert.True(t, b.IsFolderEcho("/folder", SettingCweIds, []string{"CWE-79", "CWE-89"}))
		assert.False(t, b.IsFolderEcho("/folder", SettingCweIds, []string{"CWE-79"}))
	})

	t.Run("global: bool comparison works", func(t *testing.T) {
		b := NewSentConfigBaseline()
		b.RecordGlobalValue(SettingScanAutomatic, true)
		assert.True(t, b.IsGlobalEcho(SettingScanAutomatic, true))
		assert.False(t, b.IsGlobalEcho(SettingScanAutomatic, false))
	})

	t.Run("global: RiskScoreThreshold int vs *int comparison", func(t *testing.T) {
		val := 300
		b := NewSentConfigBaseline()
		b.RecordGlobalValue(SettingRiskScoreThreshold, 300)
		assert.True(t, b.IsGlobalEcho(SettingRiskScoreThreshold, &val))
	})
}

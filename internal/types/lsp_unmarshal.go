package types

import (
	"encoding/json"
)

// UnmarshalJSON handles both the new protocol format (where settings values are objects with "value" and "changed")
// and the old protocol format (where settings values are primitive types and folderConfigs might be embedded in settings).
func (p *DidChangeConfigurationParams) UnmarshalJSON(data []byte) error {
	type Alias DidChangeConfigurationParams
	aux := &struct {
		Settings map[string]any `json:"settings,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Settings != nil {
		p.Settings = make(map[string]*ConfigSetting)

		// LSP4J wraps the payload in an extra "settings" layer:
		// {"settings": {"settings": {actual settings}, "folderConfigs": [...]}}
		// Detect and unwrap this double-nesting.
		settingsToProcess := aux.Settings
		if innerSettings, ok := aux.Settings["settings"]; ok {
			if innerMap, isMap := innerSettings.(map[string]any); isMap {
				if innerFC, hasFC := aux.Settings["folderConfigs"]; hasFC {
					folderData, _ := json.Marshal(innerFC)
					var wrappedFolders []LspFolderConfig
					if err := json.Unmarshal(folderData, &wrappedFolders); err == nil {
						p.FolderConfigs = append(p.FolderConfigs, wrappedFolders...)
					}
				}
				settingsToProcess = innerMap
			}
		}

		for key, val := range settingsToProcess {
			if key == "folderConfigs" {
				folderData, _ := json.Marshal(val)
				var oldFolders []LspFolderConfig
				if err := json.Unmarshal(folderData, &oldFolders); err == nil {
					p.FolderConfigs = append(p.FolderConfigs, oldFolders...)
				}
				continue
			}

			if valMap, isMap := val.(map[string]any); isMap {
				if _, hasChanged := valMap["changed"]; hasChanged {
					settingData, _ := json.Marshal(val)
					var cs ConfigSetting
					_ = json.Unmarshal(settingData, &cs)
					p.Settings[key] = &cs
				} else {
					p.Settings[key] = &ConfigSetting{
						Value:   val,
						Changed: true,
					}
				}
			} else {
				p.Settings[key] = &ConfigSetting{
					Value:   val,
					Changed: true, // Legacy overrides are always treated as changed
				}
			}
		}
	}
	return nil
}

func (p *InitializationOptions) UnmarshalJSON(data []byte) error {
	type Alias InitializationOptions
	aux := &struct {
		Settings map[string]any `json:"settings,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}

	// In the old format, the initialization options were sent flat (not wrapped in a settings map)
	// But let's first unmarshal to see if it matches the new format.
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Extract top-level unknown fields as legacy settings
	var flatMap map[string]any
	if err := json.Unmarshal(data, &flatMap); err == nil {
		if p.Settings == nil {
			p.Settings = make(map[string]*ConfigSetting)
		}

		knownKeys := map[string]bool{
			"settings":                true,
			"folderConfigs":           true,
			"requiredProtocolVersion": true,
			"deviceId":                true,
			"integrationName":         true,
			"integrationVersion":      true,
			"osPlatform":              true,
			"osArch":                  true,
			"runtimeVersion":          true,
			"runtimeName":             true,
			"hoverVerbosity":          true,
			"outputFormat":            true,
			"path":                    true,
			"trustedFolders":          true,
		}

		for key, val := range flatMap {
			if key == "folderConfigs" && len(p.FolderConfigs) == 0 {
				folderData, _ := json.Marshal(val)
				var oldFolders []LspFolderConfig
				if err := json.Unmarshal(folderData, &oldFolders); err == nil {
					p.FolderConfigs = append(p.FolderConfigs, oldFolders...)
				}
				continue
			}

			if !knownKeys[key] {
				p.Settings[key] = &ConfigSetting{
					Value:   val,
					Changed: true,
				}
			}
		}
	}

	if aux.Settings != nil {
		if p.Settings == nil {
			p.Settings = make(map[string]*ConfigSetting)
		}
		for key, val := range aux.Settings {
			if valMap, isMap := val.(map[string]any); isMap {
				if _, hasChanged := valMap["changed"]; hasChanged {
					settingData, _ := json.Marshal(val)
					var cs ConfigSetting
					_ = json.Unmarshal(settingData, &cs)
					p.Settings[key] = &cs
				} else {
					p.Settings[key] = &ConfigSetting{
						Value:   val,
						Changed: true,
					}
				}
			} else {
				p.Settings[key] = &ConfigSetting{
					Value:   val,
					Changed: true,
				}
			}
		}
	}
	return nil
}

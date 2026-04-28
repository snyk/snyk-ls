package util

import "github.com/snyk/go-application-framework/pkg/configuration/configresolver"

// CoerceToLocalConfigField handles both in-memory *LocalConfigField (during session)
// and map[string]interface{} (after JSON deserialization on restart).
func CoerceToLocalConfigField(val any) (*configresolver.LocalConfigField, bool) {
	if lf, ok := val.(*configresolver.LocalConfigField); ok {
		return lf, lf != nil && lf.Changed
	}
	m, ok := val.(map[string]interface{})
	if !ok {
		return nil, false
	}
	changed, _ := m["changed"].(bool)
	if !changed {
		return nil, false
	}
	return &configresolver.LocalConfigField{Value: m["value"], Changed: true}, true
}

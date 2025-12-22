// Package env provides utilities for environment variables.
package env

import (
	"maps"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/envvars"
	"github.com/subosito/gotenv"
)

// GetEnvFromSystemAndConfiguration returns the environment variables from the system and the configuration.
// It loads the environment variables from the shell into the current process environment
// After that it loads the custom config files configured in the configuration into the returned environment.
// The custom config files override the OS environment variables.
// The userSettingsPath is used to prioritize the user specified PATH over their SHELL's PATH.
// Config files can be specified in the configuration using the `configuration.CUSTOM_CONFIG_FILES` key.
func GetEnvFromSystemAndConfiguration(cfg configuration.Configuration, userSettingsPath string, logger *zerolog.Logger) gotenv.Env {
	// load the env from shell, but don't load custom config files,
	// as we don't want to load the dir-specific files into the global environment
	envvars.LoadConfiguredEnvironment([]string{}, "")

	// prioritize the user specified PATH over their SHELL's
	envvars.UpdatePath(userSettingsPath, true)

	// load current process environment into the new env
	env := gotenv.Env{}
	for _, kv := range os.Environ() {
		// Split at the first '=' only (values can contain '=')
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		env[k] = v
	}

	customConfigFiles := cfg.GetStringSlice(configuration.CUSTOM_CONFIG_FILES)

	// read all files (custom config overrides OS environment)
	for _, file := range customConfigFiles {
		e, err := gotenv.Read(file)
		if err != nil {
			logger.Warn().Err(err).Msg("Error reading custom config files")
		}
		maps.Insert(env, maps.All(e))
	}
	return env
}
